use std::{collections::HashSet, path::PathBuf, pin::Pin, process::id, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use log::{debug, error, info, warn};
use plist::{Data, Dictionary, Value};
use serde::{Deserialize, Serialize};
use tokio::{select, sync::{broadcast, Mutex}, task::JoinHandle};
use uuid::Uuid;

use crate::{aps::{get_message, APSConnection, APSInterestToken}, ids::{identity_manager::{IDSSendMessage, MessageTarget, SendJob}, user::{IDSNGMIdentity, IDSService}, CertifiedContext}, imessage::messages::ErrorMessage, util::{bin_deserialize_opt_vec, duration_since_epoch, encode_hex, plist_to_bin, ungzip}, APSMessage, ConversationData, IDSUser, Message, MessageInst, NormalMessage, OSConfig, PushError};

use crate::ids::{identity_manager::{DeliveryHandle, IdentityManager, IdentityResource}, user::{IDSUserIdentity, QueryOptions}};
use std::str::FromStr;
use rand::RngCore;
use crate::ids::IDSRecvMessage;
use async_recursion::async_recursion;

pub const MADRID_SERVICE: IDSService = IDSService {
    name: "com.apple.madrid",
    sub_services: &[
        "com.apple.private.alloy.sms",
        "com.apple.private.alloy.gelato",
        "com.apple.private.alloy.biz",
        "com.apple.private.alloy.gamecenter.imessage",
    ],
    client_data: &[
        ("is-c2k-equipment", Value::Boolean(true)),
        ("optionally-receive-typing-indicators", Value::Boolean(true)),
        ("show-peer-errors", Value::Boolean(true)),
        ("supports-ack-v1", Value::Boolean(true)),
        ("supports-activity-sharing-v1", Value::Boolean(true)),
        ("supports-audio-messaging-v2", Value::Boolean(true)),
        ("supports-autoloopvideo-v1", Value::Boolean(true)),
        ("supports-be-v1", Value::Boolean(true)),
        ("supports-ca-v1", Value::Boolean(true)),
        ("supports-fsm-v1", Value::Boolean(true)),
        ("supports-fsm-v2", Value::Boolean(true)),
        ("supports-fsm-v3", Value::Boolean(true)),
        ("supports-ii-v1", Value::Boolean(true)),
        ("supports-impact-v1", Value::Boolean(true)),
        ("supports-inline-attachments", Value::Boolean(true)),
        ("supports-keep-receipts", Value::Boolean(true)),
        ("supports-location-sharing", Value::Boolean(true)),
        ("supports-media-v2", Value::Boolean(true)),
        ("supports-photos-extension-v1", Value::Boolean(true)),
        ("supports-st-v1", Value::Boolean(true)),
        ("supports-update-attachments-v1", Value::Boolean(true)),
        ("supports-people-request-messages", Value::Boolean(true)),
        ("supports-people-request-messages-v2", Value::Boolean(true)),
        ("supports-people-request-messages-v3", Value::Boolean(true)),
        ("supports-rem", Value::Boolean(true)),
        ("nicknames-version", Value::Real(1.0)),
        ("ec-version", Value::Real(1.0)),
        ("supports-cross-platform-sharing", Value::Boolean(true)),
        ("supports-original-timestamp-v1", Value::Boolean(true)),
        ("supports-sa-v1", Value::Boolean(true)),
        ("supports-photos-extension-v2", Value::Boolean(true)),
        ("prefers-sdr", Value::Boolean(false)),
        ("supports-shared-exp", Value::Boolean(true)),
        ("supports-protobuf-payload-data-v2", Value::Boolean(true)),
        ("supports-hdr", Value::Boolean(true)),
        ("supports-heif", Value::Boolean(true)),
        ("supports-dq-nr", Value::Boolean(true)),
        ("supports-family-invite-message-bubble", Value::Boolean(true)),
        ("supports-live-delivery", Value::Boolean(true)),
        ("supports-findmy-plugin-messages", Value::Boolean(true)),
        ("supports-stick-moji-backs", Value::Boolean(true)),
        ("supports-emoji-tapbacks", Value::Boolean(true)),
        ("supports-send-later-messages", Value::Boolean(true)),
        ("supports-certified-delivery-v1", Value::Boolean(true)),
        ("supports-transcript-backgrounds", Value::Boolean(true)),
        ("supports-gti", Value::Boolean(true)),
        ("supports-polls", Value::Boolean(true)),
    ],
    flags: 17,
    capabilities_name: "Messenger"
};

impl IDSRecvMessage {
    pub fn to_message(&self, conversation: Option<ConversationData>, message: Message) -> Result<MessageInst, PushError> {
        let Self {
            sender,
            uuid: Some(uuid),
            ns_since_epoch: Some(ns_since_epoch),
            token,
            send_delivered,
            ..
        } = self else {
            return Err(PushError::BadMsg)
        };
        Ok(MessageInst {
            sender: sender.clone(),
            id: Uuid::from_bytes(uuid.clone().try_into().unwrap()).to_string().to_uppercase(),
            sent_timestamp: ns_since_epoch / 1000000,
            conversation,
            message,
            target: token.clone().map(|token| vec![MessageTarget::Token(token)]),
            send_delivered: send_delivered.unwrap_or(false),
            verification_failed: self.verification_failed,
            certified_context: self.certified_context(),
        })
    }

    pub fn certified_context(&self) -> Option<CertifiedContext> {
        let Self {
            certified_delivery_receipt: Some(receipt), 
            certified_delivery_version: Some(version), 
            sender: Some(sender), 
            target: Some(target), 
            token: Some(token), 
            uuid: Some(uuid), ..
        } = self else { return None };
        Some(CertifiedContext { version: *version, receipt: receipt.clone(), sender: sender.clone(), target: target.clone(), uuid: uuid.clone(), token: token.clone() })
    }
}

pub struct IMClient {
    pub conn: APSConnection,
    pub identity: IdentityManager,
    os_config: Arc<dyn OSConfig>,
    _interest_token: APSInterestToken,
}

impl IMClient {
    pub async fn new(conn: APSConnection, users: Vec<IDSUser>, identity: IDSNGMIdentity, services: &'static [&'static IDSService], cache_path: PathBuf, os_config: Arc<dyn OSConfig>, mut keys_updated: Box<dyn FnMut(Vec<IDSUser>) + Send + Sync>) -> IMClient {
        let interest = conn.request_topics(&["com.apple.private.alloy.sms", "com.apple.madrid"]).await;
        let _ = Self::setup_conn(&conn).await;

        let mut to_refresh = conn.generated_signal.subscribe();
        let reconn_conn = Arc::downgrade(&conn);
        tokio::spawn(async move {
            loop {
                match to_refresh.recv().await {
                    Ok(()) => {
                        let Some(conn) = reconn_conn.upgrade() else { break };
                        let _ = Self::setup_conn(&conn).await;
                    },
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let identity = IdentityResource::new(users, identity, services, cache_path, conn.clone(), os_config.clone()).await;

        let mut to_refresh = identity.generated_signal.subscribe();
        let my_ident_ref = identity.resource.clone();
        tokio::spawn(async move {
            loop {
                match to_refresh.recv().await {
                    Ok(()) => {
                        keys_updated(my_ident_ref.users.read().await.clone())
                    },
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        IMClient {
            _interest_token: interest,
            conn,
            os_config: os_config.clone(),
            identity,
        }
    }

    async fn setup_conn(conn: &APSConnection) -> Result<(), PushError> {
        if let Err(_) = tokio::time::timeout(Duration::from_millis(500), conn.wait_for_timeout(conn.subscribe().await,
            |msg| if let APSMessage::NoStorage = msg { Some(()) } else { None })).await {

            debug!("Flushing cache!");
            
            #[derive(Serialize)]
            struct FlushCacheMsg {
                c: u64,
                e: u64,
            }

            let msg = FlushCacheMsg {
                c: 160,
                e: duration_since_epoch().as_nanos() as u64,
            };

            conn.send_message("com.apple.madrid", msg, None).await?;
        }
        Ok(())
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<Option<MessageInst>, PushError> {
        if self.identity.handle(msg.clone()).await? {
            // Apple telling us our identity cache is stale. Worth recording:
            // it dates the moment our view of a peer's devices was refreshed,
            // which is the other half of any "why didn't this arrive" timeline.
            info!("IDS PeerCacheInvalidate — Apple says our identity cache is stale");
            return Ok(Some(MessageInst {
                id: Uuid::new_v4().to_string(),
                sender: None,
                conversation: None,
                message: Message::PeerCacheInvalidate,
                sent_timestamp: 0,
                target: None,
                send_delivered: false,
                verification_failed: false,
                certified_context: None,
            }))
        }
        if let Some(received) = self.identity.receive_message(msg, &["com.apple.madrid", "com.apple.private.alloy.sms"]).await? {
            // Captured before process_msg takes ownership, so the non-Ok(Some)
            // arms can still say which peer and command they came from.
            let (rx_cmd, rx_from) = (received.command, received.sender.clone());
            let rx_had_body = received.message.is_some() || received.message_unenc.is_some();
            let recieved = self.process_msg(received).await;
            // Previously only the Ok(Some) arm logged, so a message that was
            // received and then dropped was indistinguishable from one that
            // never arrived. All three arms now leave a trace.
            match &recieved {
                // .redacted() not Display: message bodies must never reach a
                // support bundle. Structure and a salted hash only.
                Ok(Some(recieved)) => info!("recieved {}", recieved.redacted()),
                // Same split as the DROP above: a bodyless control message
                // being consumed is normal and goes to debug; anything that
                // carried a body and still produced nothing is worth seeing.
                Ok(None) if rx_had_body => info!("IDS RX cmd={rx_cmd} from={rx_from:?} — had a body, produced no message"),
                Ok(None) => debug!("IDS RX cmd={rx_cmd} from={rx_from:?} — consumed, no user-visible message"),
                Err(e) => warn!("IDS RX cmd={rx_cmd} from={rx_from:?} — failed: {e}"),
            }
            recieved
        } else {
            Ok(None)
        }
    }
    
    async fn process_msg(&self, mut payload: IDSRecvMessage) -> Result<Option<MessageInst>, PushError> {
        let command = payload.command;
        // delivered/read
        if let IDSRecvMessage {
            command: 101 | 102 | 113,
            ..
        } = &payload {
            return Ok(payload.to_message(None, match command {
                101 => Message::Delivered,
                102 => Message::Read,
                113 => Message::NotifyAnyways,
                _ => panic!("no")
            }).ok())
        }

        if let IDSRecvMessage {
            sender: Some(sender),
            target: Some(target),
            is_typing: Some(0),
            message: None,
            ..
        } = &payload {
            return Ok(payload.to_message(Some(ConversationData {
                participants: vec![sender.clone(), target.clone()],
                cv_name: None,
                sender_guid: None,
                after_guid: None,
            }), Message::Typing(true, None)).ok())
        }

        // errors
        if let IDSRecvMessage {
            command: 120,
            error_for: Some(_),
            error_status: Some(error_status),
            error_string: Some(error_string),
            error_for_str: Some(for_str),
            sender: Some(sender),
            target: Some(target),
            ..
        } = &payload {
            // A peer telling us THEY could not decrypt something we sent.
            // The closest we ever get to seeing the far side's failures, so
            // it belongs in the log rather than only in the cache mutation.
            warn!("IDS 120 ERROR from={sender} to={target} for={for_str} status={error_status} str={error_string}");
            if error_string == "ec-com.apple.messageprotection-802" {
                // refreshing identity cache can fix this
                let mut cache_lock = self.identity.cache.lock().await;
                cache_lock.invalidate(&target, &sender);
            }
            return Ok(payload.to_message(None, Message::Error(ErrorMessage {
                for_uuid: for_str.clone(),
                status: *error_status,
                status_str: error_string.clone(),
            })).ok())
        }

        // TODO rewrite
        if let IDSRecvMessage {
            command: 130,
            sender: Some(sender),
            target: Some(target),
            token: Some(sender_token),
            ..
        } = &payload {
            info!("IDS 130 invalidate target={target} sender={sender}");
            let mut cache_lock = self.identity.cache.lock().await;
            cache_lock.invalidate(&target, &sender);
            return Ok(None)
        }

        if let IDSRecvMessage {
            command: 145,
            no_reply: None | Some(false),
            sender: Some(sender),
            ..
        } = &payload {
            let _ = self.send(&mut MessageInst::new(ConversationData {
                participants: vec![sender.clone()],
                cv_name: None,
                sender_guid: Some(Uuid::new_v4().to_string()),
                after_guid: None,
            }, &sender, Message::MessageReadOnDevice)).await;
        }

        if payload.message_unenc.is_none() {
            // Only a *failure* if there was an encrypted body to begin with.
            // Control traffic (send-acks, cmd 255/97) legitimately arrives
            // with no body at all — warning on those made 270 lines of
            // healthy operation look like dropped messages.
            // Silent until now. An encrypted body arrived and decryption
            // produced nothing — verification_failed tells you whether that
            // was an identity miss (see "No identity for payload!") or the
            // payload simply had no body to begin with.
            if payload.message.is_some() {
                warn!("IDS DROP cmd={} from={} uuid={} — encrypted body did not decrypt (verification_failed={})",
                    command,
                    payload.sender.as_deref().unwrap_or("-"),
                    payload.uuid.as_ref().map(|u| encode_hex(u)).unwrap_or_else(|| "-".into()),
                    payload.verification_failed);
            }
            if let Some(context) = payload.certified_context() {
                // we weren't delivered, but we got this
                self.identity.certify_delivery("com.apple.madrid", &context, false).await?;
            }
            return Ok(None);
        }

        match MessageInst::from_raw(payload.message_unenc.take().unwrap().plist()?, &payload, &self.conn).await {
            Err(PushError::BadMsg) => {
                // Also silent until now: we decrypted a body and then failed
                // to parse it. Very different from never receiving it, and
                // worth distinguishing when a peer reports missing messages.
                warn!("IDS DROP cmd={} from={} uuid={} — body decrypted but unparseable",
                    command,
                    payload.sender.as_deref().unwrap_or("-"),
                    payload.uuid.as_ref().map(|u| encode_hex(u)).unwrap_or_else(|| "-".into()));
                if let Some(context) = payload.certified_context() {
                    // we weren't delivered, but we got this
                    self.identity.certify_delivery("com.apple.madrid", &context, false).await?;
                }
                Ok(None)
            },
            Err(err) => {
                warn!("IDS ERR cmd={} from={} — {err}",
                    command, payload.sender.as_deref().unwrap_or("-"));
                Err(err)
            },
            Ok(msg) => Ok(Some(msg))
        }
    }

    pub async fn send(&self, message: &mut MessageInst) -> Result<SendJob, PushError> {
        let handles = self.identity.get_handles().await;

        let topic = if message.message.is_sms() { "com.apple.private.alloy.sms" } else { "com.apple.madrid" };

        let targets = message.prepare_send(&handles);
        self.identity.cache_keys(
            topic,
            &targets,
            message.sender.as_ref().unwrap(),
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;

        let handle = message.sender.as_ref().unwrap().to_string();
        let ident_cache = self.identity.cache.lock().await;
        let message_targets = if let Some(message_targets) = &message.target {
            ident_cache.get_targets(topic, &handle, &targets, message_targets)?
        } else {
            ident_cache.get_participants_targets(topic, &handle, &targets)
        };
        // Per-participant device counts, one line per send. This lives here
        // rather than in targets_for_handles because THIS is the path send()
        // actually takes (cache_keys + get_participants_targets directly) —
        // the version in targets_for_handles never fired once across a 7-hour
        // capture. A `:0` here means that participant resolves to no devices
        // and cannot receive anything we send.
        let target_counts = targets.iter()
            .map(|p| format!("{p}:{}", ident_cache.get_keys(topic, &handle, p).len()))
            .collect::<Vec<_>>()
            .join(" ");
        info!("IDS TARGETS {handle} → [{target_counts}]");
        drop(ident_cache);

        // if we have other people, but not a single target going to not us, we cannot "send" this message.
        if targets.iter().any(|target| !handles.contains(target)) &&
            !message_targets.iter().any(|target| !handles.contains(&target.participant)) {
            return Err(PushError::NoValidTargets);
        }
        
        let my_handles = self.identity.get_handles().await;

        if message.is_queued() {
            let mut targets = message_targets.clone();
            targets.retain(|t| t.participant == handle);

            let ids_message = message.get_ids(&my_handles, &self.conn, false).await?;
            let sendjob = self.identity.send_message(topic, ids_message, targets).await;

            if !message.message.should_schedule() {
                // we aren't actually sending this. It is just a draft
                return sendjob
            }
        }

        let ids_message = message.get_ids(&my_handles, &self.conn, true).await?;

        self.identity.send_message(topic, ids_message, message_targets).await
    }
}




