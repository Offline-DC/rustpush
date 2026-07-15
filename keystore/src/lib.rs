use std::{any::Any, error::Error, sync::OnceLock};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;


pub mod software;
pub mod backup;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum EcCurve {
    P256,
    P384,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum KeyType {
    Rsa(u16),
    Ec(EcCurve),
    Aes(u16),
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum KeystorePadding {
    PKCS1,
    OAEP {
        md: KeystoreDigest,
        mgf1: KeystoreDigest,
    },
    None
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum EncryptMode {
    Rsa (KeystorePadding),
    Gcm,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum KeystoreDigest {
    Sha384,
    Sha256,
    Sha1,
}

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("Operation not supported")]
    NotSupported,
    #[error("Key not found!")]
    KeyNotFound,
    #[error("Key already exists!")]
    KeyAlreadyExists,
    #[error("Bad key type {0:?}")]
    BadKeyType(KeyType),
    #[error("Keystore locked!")]
    KeystoreLocked,
    #[error("Key not recoverable!")]
    KeyUnrecoverable,
    #[error("Software error {0}")]
    SoftwareError(#[from] openssl::error::ErrorStack),
    #[error("Keystore error {0}")]
    KeystoreError(String),
}

static KEYSTORE: OnceLock<Box<dyn Keystore>> = OnceLock::new();

pub fn init_keystore(store: impl Keystore) {
    let _ = KEYSTORE.set(Box::new(store));
}

pub fn keystore() -> &'static dyn Keystore {
    &**KEYSTORE.get().expect("GLOBAL not initialized")
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct KeystoreAccessRules {
    pub block_modes: Vec<EncryptMode>,
    pub digests: Vec<KeystoreDigest>,
    pub encryption_paddings: Vec<KeystorePadding>,
    pub mgf1_digests: Vec<KeystoreDigest>,
    pub signature_padding: Vec<KeystorePadding>,
    pub require_user: bool,
    pub can_agree: bool,
    pub can_sign: bool,
    pub can_encrypt: bool,
    pub can_decrypt: bool,
}

pub trait LockableKeystore {
    fn lock(&self) -> Result<(), KeystoreError>;
    fn unlock(&self) -> Result<(), KeystoreError>;
    fn is_locked(&self) -> bool;
    fn recover(&self) -> Result<(), KeystoreError>;
}

pub trait Keystore: Send + Sync + 'static {
    fn as_lockable(&self) -> Option<&dyn LockableKeystore> {
        None
    }

    fn create_key(&self, alias: &str, r#type: KeyType, access_rules: KeystoreAccessRules) -> Result<(), KeystoreError>;
    fn destroy_key(&self, alias: &str) -> Result<(), KeystoreError>;
    fn list_keys(&self) -> Result<Vec<String>, KeystoreError>;

    fn set_secret(&self, alias: &str, secret: &[u8]) -> Result<(), KeystoreError>;
    fn get_secret(&self, alias: &str) -> Result<Option<Vec<u8>>, KeystoreError>;
    fn delete_secret(&self, alias: &str) -> Result<(), KeystoreError>;

    fn ensure_secret(&self, alias: &str, len: usize) -> Result<Vec<u8>, KeystoreError> {
        Ok(if let Some(secret) = self.get_secret(alias)? {
            secret
        } else {
            let mut bytes = vec![0u8; len];
            rand::thread_rng().fill_bytes(&mut bytes);
            self.set_secret(alias, &bytes)?;
            bytes
        })
    }

    // priv key can be EC private key in DER, raw AES key bytes
    // or a DER RSA private key.
    fn import_key(&self, alias: &str, r#type: KeyType, priv_key: &[u8], access_rules: KeystoreAccessRules) -> Result<(), KeystoreError>;
    fn get_key_type(&self, alias: &str) -> Result<Option<KeyType>, KeystoreError>;
    
    fn sign(&self, alias: &str, digest: KeystoreDigest, padding: KeystorePadding, data: &[u8]) -> Result<Vec<u8>, KeystoreError>;
    fn verify(&self, alias: &str, digest: KeystoreDigest, padding: KeystorePadding, data: &[u8], sig: &[u8]) -> Result<bool, KeystoreError>;
    // returns in DER
    fn get_public_key(&self, alias: &str) -> Result<Vec<u8>, KeystoreError>;
    // peer is a EC public key starting with 02, 03, or 04
    fn derive(&self, alias: &str, peer: &[u8]) -> Result<Vec<u8>, KeystoreError>;

    fn encrypt(&self, alias: &str, plaintext: &[u8], mode: &mut EncryptMode) -> Result<Vec<u8>, KeystoreError>;
    fn decrypt(&self, alias: &str, ciphertext: &[u8], mode: &EncryptMode) -> Result<Vec<u8>, KeystoreError>;

    fn ensure_exists(&self, alias: &str, r#type: KeyType, access_rules: KeystoreAccessRules) -> Result<(), KeystoreError> {
        if self.get_key_type(alias)?.is_some() {
            return Ok(())
        }

        self.create_key(alias, r#type, access_rules)?;

        Ok(())
    }

    fn overwrite_new(&self, alias: &str, r#type: KeyType, access_rules: KeystoreAccessRules) -> Result<(), KeystoreError> {
        self.destroy_key(alias)?;
        self.create_key(alias, r#type, access_rules)?;
        Ok(())
    }

    fn create_new(&self, prefix: &str, r#type: KeyType, access_rules: KeystoreAccessRules) -> Result<String, KeystoreError> {
        let alias = format!("{prefix}:{}", rand::thread_rng().next_u64());
        
        self.create_key(&alias, r#type, access_rules)?;

        Ok(alias)
    }
}

pub trait KeystoreKey {
    fn alias(&self) -> &str;
}

pub trait KeystorePublicKey: KeystoreKey {
    fn get_public_key(&self) -> Result<Vec<u8>, KeystoreError> {
        keystore().get_public_key(&self.alias())
    }
}

pub trait KeystoreDeriveKey: KeystoreKey {
    fn derive(&self, peer: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        keystore().derive(&self.alias(), peer)
    }
}

pub trait KeystoreSignKey: KeystorePublicKey {
    fn sign(&self, digest: KeystoreDigest, padding: KeystorePadding, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        keystore().sign(self.alias(), digest, padding, data)
    }
    
    fn verify(&self, digest: KeystoreDigest, padding: KeystorePadding, data: &[u8], sig: &[u8]) -> Result<bool, KeystoreError> {
        keystore().verify(self.alias(), digest, padding, data, sig)
    }
}

pub trait KeystoreEncryptKey: KeystoreKey {
    fn encrypt(&self, plaintext: &[u8], mode: &mut EncryptMode) -> Result<Vec<u8>, KeystoreError> {
        keystore().encrypt(&self.alias(), plaintext, mode)
    }

    fn decrypt(&self, ciphertext: &[u8], mode: &EncryptMode) -> Result<Vec<u8>, KeystoreError> {
        keystore().decrypt(&self.alias(), ciphertext, mode)
    }
}

#[derive(Serialize, Clone)]
pub struct RsaKey(pub String);

// RsaKey serializes as its keystore ALIAS (a `<string>`), and historically only
// deserialized from that alias. But some builds — notably OpenBubbles releases on an
// older rustpush — persisted the RSA private-key MATERIAL inline as raw PKCS#1 DER
// (`<data>`) instead of a keystore alias. To migrate those without forcing a
// re-registration, accept EITHER on-disk form:
//   • `<string>` -> an existing keystore alias  (unchanged behaviour; the common case)
//   • `<data>`   -> raw PKCS#1 DER -> import into the process keystore under a
//                   content-derived alias, then use that alias.
// This is the single bridge that lets `push.keypair` and every `id.plist` keypair load
// regardless of which scheme produced them. Identity keys are unaffected (they use their
// own inline openssl (de)serializers).
impl<'de> Deserialize<'de> for RsaKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RsaKeyVisitor;
        impl<'de> serde::de::Visitor<'de> for RsaKeyVisitor {
            type Value = RsaKey;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a keystore alias string, or raw PKCS#1 RSA private-key DER bytes")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<RsaKey, E> {
                Ok(RsaKey(v.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<RsaKey, E> {
                Ok(RsaKey(v))
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<RsaKey, E> {
                RsaKey::import_der(v).map_err(serde::de::Error::custom)
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<RsaKey, E> {
                RsaKey::import_der(&v).map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_any(RsaKeyVisitor)
    }
}

impl RsaKey {
    /// Import raw PKCS#1 RSA private-key DER into the process keystore and return an
    /// aliased handle. The alias is derived from the key bytes, so importing the same
    /// material twice is a no-op (idempotent — `KeyAlreadyExists` is treated as success).
    /// Used to migrate identities that stored key material inline rather than as an alias.
    pub fn import_der(der: &[u8]) -> Result<Self, KeystoreError> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(der);
        let alias = format!(
            "imported:rsa:{}",
            hash.iter().take(10).map(|b| format!("{b:02x}")).collect::<String>()
        );
        // bits is informational for import (the software keystore parses the DER and
        // ignores it); pass a nominal value.
        match keystore().import_key(&alias, KeyType::Rsa(2048), der, KeystoreAccessRules::default()) {
            Ok(()) | Err(KeystoreError::KeyAlreadyExists) => Ok(Self(alias)),
            Err(e) => Err(e),
        }
    }

    pub fn overwrite(key: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().overwrite_new(key, KeyType::Rsa(bits), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn ensure(key: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().ensure_exists(key, KeyType::Rsa(bits), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn create_new(prefix: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        let key = keystore().create_new(prefix, KeyType::Rsa(bits), access_rules)?;
        Ok(Self(key))
    }
    
    pub fn import(key: &str, bits: u16, priv_key: &[u8], access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().import_key(key, KeyType::Rsa(bits), priv_key, access_rules)?;
        Ok(Self(key.to_string()))
    }
}

impl KeystoreKey for RsaKey {
    fn alias(&self) -> &str {
        &self.0
    }
}
impl KeystorePublicKey for RsaKey { }
impl KeystoreEncryptKey for RsaKey { }
impl KeystoreSignKey for RsaKey { }
#[derive(Serialize, Deserialize, Clone)]
pub struct EcKeystoreKey(pub String);
impl EcKeystoreKey {
    pub fn overwrite(key: &str, curve: EcCurve, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().overwrite_new(key, KeyType::Ec(curve), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn ensure(key: &str, curve: EcCurve, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().ensure_exists(key, KeyType::Ec(curve), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn create_new(prefix: &str, curve: EcCurve, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        let key = keystore().create_new(prefix, KeyType::Ec(curve), access_rules)?;
        Ok(Self(key))
    }

    pub fn import(key: &str, curve: EcCurve, priv_key: &[u8], access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().import_key(key, KeyType::Ec(curve), priv_key, access_rules)?;
        Ok(Self(key.to_string()))
    }
}
impl KeystoreKey for EcKeystoreKey {
    fn alias(&self) -> &str {
        &self.0
    }
}
impl KeystorePublicKey for EcKeystoreKey { }
impl KeystoreSignKey for EcKeystoreKey { }
impl KeystoreDeriveKey for EcKeystoreKey { }

#[derive(Serialize, Deserialize, Clone)]
pub struct AesKeystoreKey(pub String);
impl AesKeystoreKey {
    pub fn overwrite(key: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().overwrite_new(key, KeyType::Aes(bits), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn ensure(key: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().ensure_exists(key, KeyType::Aes(bits), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn create_new(prefix: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        let key = keystore().create_new(prefix, KeyType::Aes(bits), access_rules)?;
        Ok(Self(key))
    }

    pub fn import(key: &str, bits: u16, priv_key: &[u8], access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().import_key(key, KeyType::Aes(bits), priv_key, access_rules)?;
        Ok(Self(key.to_string()))
    }
}
impl KeystoreKey for AesKeystoreKey {
    fn alias(&self) -> &str {
        &self.0
    }
}
impl KeystoreEncryptKey for AesKeystoreKey { }