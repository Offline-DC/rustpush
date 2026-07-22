//! `MacOSConfigRemote` — a copy of [`crate::macos::MacOSConfig`] whose ONLY
//! difference is how validation data is produced: instead of local absinthe
//! (`ValidationCtx`), it drives a self-hosted **NAC validation server**. Every
//! other field/method is identical to `MacOSConfig`, so the device it describes
//! stays perfectly consistent with its dumb file (same identity → Apple accepts
//! it, exactly like OpenBubbles).
//!
//! `generate_validation_data()` flow (see the NAC Validation API):
//!   1. Fetch Apple's validation certificate chain.
//!   2. POST the raw hardware-config body (the OpenBubbles **dumb file**) to
//!      `POST {NAC_BASE_URL}/nac/create`, with the cert chain in the
//!      `X-Absinthe-Cert-Chain` header. → `{ id, sign_url, request }`.
//!   3. base64-decode `request` (an OpenAbsinthe session-info-request).
//!   4. Send it to Apple's validation-initialize endpoint → `session-info`.
//!   5. POST that `session-info` to the returned `sign_url`.
//!   6. The sign response body IS the validation data.
//!
//! The NAC server and the anisette-v3 server are the same host (`NAC_BASE_URL`,
//! http on the LAN).

use std::{collections::HashMap, time::{Duration, SystemTime}};

use async_trait::async_trait;
use base64::Engine;
use plist::{Data, Dictionary, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{activation::ActivationInfo, util::{encode_hex, get_bag, REQWEST, plist_to_buf, base64_encode, base64_decode, IDS_BAG}, DebugMeta, OSConfig, PushError, RegisterMeta};

/// The subset of the Mac hardware identity the **remote** NAC path needs.
///
/// Deliberately self-contained and NOT `open_absinthe::nac::HardwareConfig`:
/// the remote path must not pull in open-absinthe (or unicorn) at all. It
/// deserializes from the very same on-disk plist OpenBubbles wrote — open-absinthe
/// serialized its byte fields with serde's `serialize_bytes` (a plist `<data>`
/// element), which `plist::Data` reads back identically. Extra keys present in
/// that dictionary (`io_mac_address`, `platform_uuid`, the `*_enc` variants, …)
/// are the ones the local emulator needed and the remote server doesn't, so
/// serde simply ignores them here.
#[derive(Serialize, Deserialize, Clone)]
pub struct HardwareConfig {
    pub product_name: String,
    pub platform_serial_number: String,
    pub os_build_num: String,
    pub mlb: String,
    /// ROM bytes, stored as a plist `<data>` element (matches open-absinthe).
    pub rom: Data,
}

/// NAC validation server (also serves anisette v3). Public host, https.
pub const NAC_BASE_URL: &str = "https://hw.openbubbles.app";

/// Where the raw hardware-config body is read from when not supplied inline —
/// the OpenBubbles dumb file. Overridable at runtime with `SMARTTXT_DUMB_PATH`.
pub const DEFAULT_DUMB_PATH: &str = "/data/data/com.openbubbles.messaging/files/dumb";

#[derive(Serialize, Deserialize, Clone)]
pub struct MacOSConfigRemote {
    pub inner: HardwareConfig,

    // software
    pub version: String,
    pub protocol_version: u32,
    pub device_id: String,
    pub icloud_ua: String,
    pub aoskit_version: String,
    pub udid: Option<String>,

    /// Raw hardware-config body for `POST /nac/create` (first 5 bytes ignored +
    /// protobuf `HwInfo`). When `None`, it's read from the dumb file
    /// ([`DEFAULT_DUMB_PATH`] / `SMARTTXT_DUMB_PATH`).
    #[serde(default)]
    pub hw_config: Option<Data>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct SessionInfoRequest {
    session_info_request: Data,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct SessionInfoResponse {
    session_info: Data,
}

#[derive(Deserialize)]
struct CertsResponse {
    cert: Data,
}

/// `POST /nac/create` response (extra fields like `id`/`expires_at` are ignored).
#[derive(Deserialize)]
struct NacCreateResponse {
    /// e.g. `/nac/<session id>/sign`
    sign_url: String,
    /// base64 OpenAbsinthe session-info-request bytes.
    request: String,
}

/// Minimal protobuf field reader — just enough to pull the dumb's `HwInfo` fields
/// (length-delimited strings/bytes + varints). Keeps the last value seen per field number
/// (fine for these singular fields); no external protobuf dependency needed.
struct ProtoFields {
    ld: std::collections::HashMap<u64, Vec<u8>>,
    varint: std::collections::HashMap<u64, u64>,
}

impl ProtoFields {
    fn parse(mut buf: &[u8]) -> ProtoFields {
        fn read_varint(buf: &mut &[u8]) -> Option<u64> {
            let (mut result, mut shift) = (0u64, 0u32);
            loop {
                let (&byte, rest) = buf.split_first()?;
                *buf = rest;
                result |= u64::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    return Some(result);
                }
                shift += 7;
                if shift >= 64 {
                    return None;
                }
            }
        }
        let mut f = ProtoFields {
            ld: std::collections::HashMap::new(),
            varint: std::collections::HashMap::new(),
        };
        while !buf.is_empty() {
            let Some(key) = read_varint(&mut buf) else { break };
            let (field, wire) = (key >> 3, key & 7);
            match wire {
                0 => match read_varint(&mut buf) {
                    Some(v) => {
                        f.varint.insert(field, v);
                    }
                    None => break,
                },
                1 => {
                    if buf.len() < 8 {
                        break;
                    }
                    buf = &buf[8..];
                }
                2 => {
                    let Some(len) = read_varint(&mut buf) else { break };
                    let len = len as usize;
                    if buf.len() < len {
                        break;
                    }
                    f.ld.insert(field, buf[..len].to_vec());
                    buf = &buf[len..];
                }
                5 => {
                    if buf.len() < 4 {
                        break;
                    }
                    buf = &buf[4..];
                }
                _ => break,
            }
        }
        f
    }
    fn bytes(&self, field: u64) -> Option<&[u8]> {
        self.ld.get(&field).map(Vec::as_slice)
    }
    fn string(&self, field: u64) -> Option<String> {
        self.ld.get(&field).and_then(|v| String::from_utf8(v.clone()).ok())
    }
    fn get_varint(&self, field: u64) -> Option<u64> {
        self.varint.get(&field).copied()
    }
}

impl MacOSConfigRemote {
    /// Build a full config from the OpenBubbles `dumb` body (the DECODED bytes: a 5-byte
    /// "OABS\0" header + a protobuf `HwInfo`). BOTH the hardware identity (nested field 1)
    /// and the software identity (top-level version / protocol / device-UUID / iCloud-UA /
    /// AOSKit) live in the dumb, so os_config.plist is not required. `hw_config` is set to
    /// the full body so `/nac/create` still receives the exact bytes it expects.
    ///
    /// Field map (confirmed against a real device dump):
    ///   top    #1 nested HwInfo   #2 macOS version   #3 protocol_version (varint)
    ///          #4 device UUID      #5 iCloud UA        #6 AOSKit version
    ///   nested #1 product_name     #2 rom (6 bytes)    #3 serial
    ///          #7 build number      #13 mlb
    pub fn from_dumb_body(body: &[u8]) -> Result<MacOSConfigRemote, PushError> {
        fn bad(m: String) -> PushError {
            PushError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidData, m))
        }
        if body.len() <= 5 {
            return Err(bad(format!(
                "dumb body is {} B — too short for the 5-byte header + HwInfo",
                body.len()
            )));
        }
        let top = ProtoFields::parse(&body[5..]);
        let hw_blob = top
            .bytes(1)
            .ok_or_else(|| bad("dumb: no nested HwInfo (top field #1)".into()))?;
        let hw = ProtoFields::parse(hw_blob);

        let need = |f: &ProtoFields, n: u64, what: &str| -> Result<String, PushError> {
            f.string(n).ok_or_else(|| bad(format!("dumb: missing {what} (field #{n})")))
        };
        let inner = HardwareConfig {
            product_name: need(&hw, 1, "product_name")?,
            platform_serial_number: need(&hw, 3, "serial")?,
            os_build_num: need(&hw, 7, "build number")?,
            mlb: need(&hw, 13, "mlb")?,
            rom: hw
                .bytes(2)
                .ok_or_else(|| bad("dumb: missing rom (nested field #2)".into()))?
                .to_vec()
                .into(),
        };
        let device_id = need(&top, 4, "device UUID")?;
        let cfg = MacOSConfigRemote {
            version: need(&top, 2, "macOS version")?,
            protocol_version: top.get_varint(3).unwrap_or(1640) as u32,
            icloud_ua: need(&top, 5, "iCloud UA")?,
            aoskit_version: need(&top, 6, "AOSKit version")?,
            udid: Some(device_id.clone()),
            device_id,
            hw_config: Some(body.to_vec().into()),
            inner,
        };
        Ok(cfg)
    }

    /// The raw hardware-config bytes for `/nac/create`: the inline `hw_config` if
    /// set, else the OpenBubbles dumb file. OpenBubbles stores it base64-encoded
    /// (like OABS); we decode it, falling back to the raw bytes if it isn't base64.
    fn hw_config_body(&self) -> Result<Vec<u8>, PushError> {
        if let Some(d) = &self.hw_config {
            let v: Vec<u8> = d.clone().into();
            if !v.is_empty() {
                return Ok(v);
            }
        }
        let path = std::env::var("SMARTTXT_DUMB_PATH").unwrap_or_else(|_| DEFAULT_DUMB_PATH.to_string());
        let raw = std::fs::read(&path).map_err(|e| {
            PushError::IoError(std::io::Error::new(std::io::ErrorKind::Other, format!("read dumb file {path}: {e}")))
        })?;
        let txt = String::from_utf8_lossy(&raw);
        match base64::engine::general_purpose::STANDARD.decode(txt.trim()) {
            Ok(decoded) if !decoded.is_empty() => Ok(decoded),
            _ => Ok(raw),
        }
    }
}

#[async_trait]
impl OSConfig for MacOSConfigRemote {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo {
        ActivationInfo {
            activation_randomness: Uuid::new_v4().to_string().to_uppercase(),
            activation_state: "Unactivated",
            build_version: self.inner.os_build_num.clone(),
            device_cert_request: csr.into(),
            device_class: "MacOS".to_string(),
            product_type: self.inner.product_name.clone(),
            product_version: self.version.clone(),
            serial_number: self.inner.platform_serial_number.clone(),
            unique_device_id: self.device_id.clone().to_uppercase(),
        }
    }

    fn get_udid(&self) -> String {
        self.udid.clone().expect("missing udid!")
    }

    fn get_normal_ua(&self, item: &str) -> String {
        let part = self.icloud_ua.split_once(char::is_whitespace).unwrap().0;
        format!("{item} {part}")
    }

    fn get_aoskit_version(&self) -> String {
        self.aoskit_version.clone()
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!("<{}> <macOS;{};{}> <{}>", self.inner.product_name, self.version, self.inner.os_build_num, for_item)
    }

    fn get_version_ua(&self) -> String {
        format!("[macOS,{},{},{}]", self.version, self.inner.os_build_num, self.inner.product_name)
    }

    fn get_activation_device(&self) -> String {
        "MacOS".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.device_id.clone()
    }

    fn get_device_name(&self) -> String {
        format!("Mac-{}", self.inner.platform_serial_number)
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        // Every network hop below is bounded (NET_TIMEOUT) so a stuck NAC LAN server
        // or Apple endpoint fails with an error instead of hanging the whole
        // registration forever. Each step is logged with elapsed time so a hang is
        // pinpointed in logcat (tag `smarttxt_ffi`/`rustpush`).
        const NET_TIMEOUT: Duration = Duration::from_secs(20);
        let t0 = std::time::Instant::now();
        log::info!("nac: generating validation data (server {NAC_BASE_URL})");

        // 1. Apple's validation certificate chain.
        let url = get_bag(IDS_BAG, "id-validation-cert").await?.into_string().unwrap();
        log::info!("nac: [1/5] fetching Apple validation cert chain…");
        let key = REQWEST.get(url).timeout(NET_TIMEOUT).send().await
            .map_err(|e| { log::error!("nac: [1/5] cert-chain fetch failed: {e}"); e })?;
        let response: CertsResponse = plist::from_bytes(&key.bytes().await?)?;
        let certs: Vec<u8> = response.cert.into();
        log::info!("nac: [1/5] cert chain ok ({} bytes, {:?})", certs.len(), t0.elapsed());

        // 2. Create a NAC session: POST the raw hardware-config body (dumb file)
        //    with the cert chain in X-Absinthe-Cert-Chain.
        let body = self.hw_config_body()?;
        log::info!("nac: [2/5] POST {NAC_BASE_URL}/nac/create (hw body {} bytes)…", body.len());
        let create = REQWEST.post(format!("{NAC_BASE_URL}/nac/create"))
            .header("X-Absinthe-Cert-Chain", base64_encode(&certs))
            .header("Content-Type", "application/octet-stream")
            .timeout(NET_TIMEOUT)
            .body(body)
            .send().await
            .map_err(|e| { log::error!("nac: [2/5] /nac/create failed (is {NAC_BASE_URL} reachable?): {e}"); e })?;
        if !create.status().is_success() {
            let code = create.status().as_u16();
            let text = create.text().await.unwrap_or_default();
            log::error!("nac: [2/5] /nac/create HTTP {code}: {text}");
            return Err(PushError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other, format!("nac/create HTTP {code}: {text}"))));
        }
        let create: NacCreateResponse = create.json().await?;
        log::info!("nac: [2/5] session created (sign_url={}, request {} chars, {:?})",
            create.sign_url, create.request.len(), t0.elapsed());

        // 3. base64-decode the session-info-request the server produced.
        let request_bytes = base64_decode(&create.request);

        // 4. Hand it to Apple's validation-initialize endpoint → session-info.
        let init = SessionInfoRequest { session_info_request: request_bytes.into() };
        let info = plist_to_buf(&init)?;
        let url = get_bag(IDS_BAG, "id-initialize-validation").await?.into_string().unwrap();
        log::info!("nac: [3/5] POST Apple id-initialize-validation…");
        let activation = REQWEST.post(url).timeout(NET_TIMEOUT).body(info).send().await
            .map_err(|e| { log::error!("nac: [3/5] Apple initialize-validation failed: {e}"); e })?;
        let response: SessionInfoResponse = plist::from_bytes(&activation.bytes().await?)?;
        let session_info: Vec<u8> = response.session_info.into();
        log::info!("nac: [4/5] Apple returned session-info ({} bytes, {:?})", session_info.len(), t0.elapsed());

        // 5. Sign: POST Apple's session-info to the session's sign_url (single-use).
        //    The response body IS the validation data.
        log::info!("nac: [5/5] POST {NAC_BASE_URL}{} (sign)…", create.sign_url);
        let signed = REQWEST.post(format!("{NAC_BASE_URL}{}", create.sign_url))
            .header("Content-Type", "application/octet-stream")
            .timeout(NET_TIMEOUT)
            .body(session_info)
            .send().await
            .map_err(|e| { log::error!("nac: [5/5] sign request failed: {e}"); e })?;
        if !signed.status().is_success() {
            let code = signed.status().as_u16();
            let text = signed.text().await.unwrap_or_default();
            log::error!("nac: [5/5] sign HTTP {code}: {text}");
            return Err(PushError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other, format!("nac sign HTTP {code}: {text}"))));
        }
        let data = signed.bytes().await?.to_vec();
        log::info!("nac: ✅ validation data ready ({} bytes, total {:?})", data.len(), t0.elapsed());
        Ok(data)
    }

    fn get_protocol_version(&self) -> u32 {
        self.protocol_version
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: self.inner.product_name.clone(),
            os_version: format!("macOS,{},{}", self.version, self.inner.os_build_num),
            software_version: self.inner.os_build_num.clone(),
        }
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: self.version.clone(),
            hardware_version: self.inner.product_name.clone(),
            serial_number: self.inner.platform_serial_number.clone(),
        }
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        let rom: Vec<u8> = self.inner.rom.clone().into();
        [
            ("X-Apple-I-MLB".to_string(), self.inner.mlb.clone()),
            ("X-Apple-I-ROM".to_string(), encode_hex(&rom)), // intentional lowercase
            ("X-Apple-I-SRL-NO".to_string(), self.inner.platform_serial_number.clone()),
        ].into_iter().collect()
    }

    fn get_serial_number(&self) -> String {
        self.inner.platform_serial_number.clone()
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/signin/v2/login"
    }

    fn get_private_data(&self) -> Dictionary {
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        Dictionary::from_iter([
            ("ap", Value::String("0".to_string())), // 1 for ios

            ("d", Value::String(format!("{:.6}", apple_epoch.elapsed().unwrap().as_secs_f64()))),
            ("dt", Value::Integer(1.into())),
            ("gt", Value::String("0".to_string())),
            ("h", Value::String("1".to_string())),
            ("m", Value::String("0".to_string())),
            ("p", Value::String("0".to_string())),

            ("pb", Value::String(self.inner.os_build_num.clone())),
            ("pn", Value::String("macOS".to_string())),
            ("pv", Value::String(self.version.clone())),

            ("s", Value::String("0".to_string())),
            ("t", Value::String("0".to_string())),
            ("u", Value::String(self.device_id.clone().to_uppercase())),
            ("v", Value::String("1".to_string())),
        ])
    }
}
