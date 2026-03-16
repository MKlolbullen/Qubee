use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use qubee_crypto::native_contract::{self, PublicIdentityBundle};
use qubee_crypto::relay_protocol::{RelayContactRequest, RelayEnvelope, RelayFrame, RelayReadCursor, RelayReceipt};
use qubee_crypto::relay_security::{BindingDecision, HandleBindingRegistry, RateLimitDecision, RateLimitRegistry};
use std::collections::{HashMap, HashSet};
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_rustls::rustls::{self, pki_types::CertificateDer, pki_types::PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};
use uuid::Uuid;

type DeviceTxMap = HashMap<String, mpsc::UnboundedSender<RelayFrame>>;

const MAX_QUEUE_PER_HANDLE: usize = 512;
const MAX_HISTORY_PER_HANDLE: usize = 4096;
const MAX_SEEN_IDS: usize = 16384;
const MAX_TEXT_FRAME_BYTES: usize = 256 * 1024;
const CONNECTION_RATE_CAPACITY: u32 = 12;
const CONNECTION_RATE_REFILL_PER_SECOND: u32 = 3;
const PREAUTH_RATE_CAPACITY: u32 = 30;
const PREAUTH_RATE_REFILL_PER_SECOND: u32 = 10;
const AUTHENTICATED_RATE_CAPACITY: u32 = 240;
const AUTHENTICATED_RATE_REFILL_PER_SECOND: u32 = 120;
const RATE_LIMIT_STALE_WINDOW_MS: u64 = 10 * 60 * 1000;

struct RelayState {
    clients: HashMap<String, DeviceTxMap>,
    bindings: HandleBindingRegistry,
    pending_relink_channels: HashMap<String, mpsc::UnboundedSender<RelayFrame>>,
    queued_messages: HashMap<String, Vec<RelayEnvelope>>,
    queued_contact_requests: HashMap<String, Vec<RelayContactRequest>>,
    message_history: HashMap<String, Vec<RelayEnvelope>>,
    contact_request_history: HashMap<String, Vec<RelayContactRequest>>,
    receipt_history: HashMap<String, Vec<RelayReceipt>>,
    read_cursor_history: HashMap<String, Vec<RelayReadCursor>>,
    delivered_message_ids: HashSet<String>,
    seen_receipt_ids: HashSet<String>,
    seen_read_cursor_ids: HashSet<String>,
    connection_limits: RateLimitRegistry,
    preauth_limits: RateLimitRegistry,
    authenticated_limits: RateLimitRegistry,
}

impl Default for RelayState {
    fn default() -> Self {
        Self {
            clients: HashMap::new(),
            bindings: HandleBindingRegistry::default(),
            pending_relink_channels: HashMap::new(),
            queued_messages: HashMap::new(),
            queued_contact_requests: HashMap::new(),
            message_history: HashMap::new(),
            contact_request_history: HashMap::new(),
            receipt_history: HashMap::new(),
            read_cursor_history: HashMap::new(),
            delivered_message_ids: HashSet::new(),
            seen_receipt_ids: HashSet::new(),
            seen_read_cursor_ids: HashSet::new(),
            connection_limits: RateLimitRegistry::new(CONNECTION_RATE_CAPACITY, CONNECTION_RATE_REFILL_PER_SECOND),
            preauth_limits: RateLimitRegistry::new(PREAUTH_RATE_CAPACITY, PREAUTH_RATE_REFILL_PER_SECOND),
            authenticated_limits: RateLimitRegistry::new(AUTHENTICATED_RATE_CAPACITY, AUTHENTICATED_RATE_REFILL_PER_SECOND),
        }
    }
}

fn bounded_push<T>(map: &mut HashMap<String, Vec<T>>, key: String, value: T, max: usize) {
    let queue = map.entry(key).or_default();
    queue.push(value);
    if queue.len() > max {
        let overflow = queue.len() - max;
        queue.drain(0..overflow);
    }
}

fn bounded_insert(set: &mut HashSet<String>, value: String, max: usize) {
    if set.len() >= max {
        set.clear();
    }
    set.insert(value);
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let bind = std::env::var("QUBEE_RELAY_BIND").unwrap_or_else(|_| "0.0.0.0:8787".to_string());
    let tls_acceptor = load_tls_acceptor()?;
    let listener = TcpListener::bind(&bind).await?;
    tracing::info!(bind = %bind, tls = tls_acceptor.is_some(), "relay listening");

    let state = Arc::new(RwLock::new(RelayState::default()));
    loop {
        let (stream, addr) = listener.accept().await?;
        let remote_ip = addr.ip().to_string();
        let allow_connection = {
            let mut state_guard = state.write().await;
            state_guard.connection_limits.purge_stale(RATE_LIMIT_STALE_WINDOW_MS);
            matches!(state_guard.connection_limits.check(&remote_ip, 1), RateLimitDecision::Allowed)
        };
        if !allow_connection {
            tracing::warn!(ip = %remote_ip, "dropping connection: rate limit exceeded");
            continue;
        }
        let state = state.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, state, remote_ip.clone(), tls_acceptor).await {
                tracing::warn!(ip = %remote_ip, error = %error, "relay connection error");
            }
        });
    }
}

async fn handle_connection(stream: TcpStream, state: Arc<RwLock<RelayState>>, remote_ip: String, tls_acceptor: Option<TlsAcceptor>) -> Result<()> {
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(stream).await.context("tls accept failed")?;
        let ws_stream = accept_async(tls_stream).await?;
        drive_connection(ws_stream, state, remote_ip).await
    } else {
        let ws_stream = accept_async(stream).await?;
        drive_connection(ws_stream, state, remote_ip).await
    }
}

async fn drive_connection<S>(ws_stream: WebSocketStream<S>, state: Arc<RwLock<RelayState>>, remote_ip: String) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<RelayFrame>();

    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let text = serde_json::to_string(&frame)?;
            ws_sender.send(Message::Text(text.into())).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    let mut authenticated_handle: Option<String> = None;
    let mut announced_device_id: Option<String> = None;
    let relay_session_id = Uuid::new_v4().to_string();
    let mut expected_challenge: Option<String> = None;
    let mut pending_relink_token: Option<String> = None;

    while let Some(message) = ws_receiver.next().await {
        let message = message?;
        if !message.is_text() {
            continue;
        }
        let payload_text = message.to_text()?;
        if payload_text.len() > MAX_TEXT_FRAME_BYTES {
            let _ = tx.send(RelayFrame::Error { message: "frame too large".into() });
            continue;
        }
        let limiter_key = authenticated_handle.clone().unwrap_or_else(|| format!("preauth:{remote_ip}"));
        let rate_limit = {
            let mut state_guard = state.write().await;
            state_guard.preauth_limits.purge_stale(RATE_LIMIT_STALE_WINDOW_MS);
            state_guard.authenticated_limits.purge_stale(RATE_LIMIT_STALE_WINDOW_MS);
            if authenticated_handle.is_some() {
                state_guard.authenticated_limits.check(&limiter_key, 1)
            } else {
                state_guard.preauth_limits.check(&limiter_key, 1)
            }
        };
        if let RateLimitDecision::Denied { retry_after_ms } = rate_limit {
            let _ = tx.send(RelayFrame::Error { message: format!("rate limit exceeded; retry in {retry_after_ms} ms") });
            continue;
        }
        let frame: RelayFrame = serde_json::from_str(payload_text).context("failed to decode relay frame")?;

        match frame {
            RelayFrame::Hello { handle, device_id, public_bundle_base64: _, .. } => {
                announced_device_id = Some(device_id.clone());
                let challenge = Uuid::new_v4().to_string();
                expected_challenge = Some(challenge.clone());
                let _ = tx.send(RelayFrame::Challenge {
                    relay_session_id: relay_session_id.clone(),
                    challenge,
                });
                if authenticated_handle.is_none() {
                    tracing::info!(handle = %handle, device = %device_id, "hello received, issuing challenge");
                }
            }
            RelayFrame::Authenticate {
                handle,
                relay_session_id: candidate_session,
                challenge,
                public_bundle_base64,
                identity_fingerprint,
                signature_base64,
            } => {
                let expected = expected_challenge.clone().ok_or_else(|| anyhow!("challenge missing"))?;
                if candidate_session != relay_session_id || expected != challenge {
                    let _ = tx.send(RelayFrame::Error {
                        message: "challenge mismatch".into(),
                    });
                    continue;
                }

                let signed_payload = format!("{relay_session_id}:{challenge}");
                let signature = STANDARD_NO_PAD.decode(signature_base64)?;
                match native_contract::verify_relay_signature(&public_bundle_base64, signed_payload.as_bytes(), &signature) {
                    Ok(_) => {
                        let device_id = announced_device_id.clone().unwrap_or_else(|| "unknown-device".to_string());
                        let public_bundle_json = STANDARD_NO_PAD.decode(&public_bundle_base64)?;
                        let public_bundle: PublicIdentityBundle = serde_json::from_slice(&public_bundle_json)
                            .context("authenticate carried an invalid public bundle")?;
                        if public_bundle.relay_handle != handle {
                            let _ = tx.send(RelayFrame::Error { message: "public bundle handle mismatch".into() });
                            continue;
                        }
                        if public_bundle.device_id != device_id {
                            let _ = tx.send(RelayFrame::Error { message: "public bundle device mismatch".into() });
                            continue;
                        }
                        if public_bundle.identity_fingerprint != identity_fingerprint {
                            let _ = tx.send(RelayFrame::Error { message: "public bundle fingerprint mismatch".into() });
                            continue;
                        }
                        let binding_decision = {
                            let mut state_guard = state.write().await;
                            state_guard
                                .bindings
                                .validate_or_bind(&handle, &device_id, &identity_fingerprint, &public_bundle_base64)?
                        };

                        match binding_decision {
                            BindingDecision::NewBinding | BindingDecision::ExistingBinding => {
                                let (queued_messages, queued_requests, queued_receipts, queued_cursors) = {
                                    let mut state_guard = state.write().await;
                                    if let Some(token) = pending_relink_token.clone() {
                                        state_guard.pending_relink_channels.remove(&token);
                                    }
                                    state_guard.clients.entry(handle.clone()).or_default().insert(device_id.clone(), tx.clone());
                                    (
                                        state_guard.queued_messages.remove(&handle).unwrap_or_default(),
                                        state_guard.queued_contact_requests.remove(&handle).unwrap_or_default(),
                                        state_guard.receipt_history.get(&handle).cloned().unwrap_or_default(),
                                        state_guard.read_cursor_history.get(&handle).cloned().unwrap_or_default(),
                                    )
                                };

                                authenticated_handle = Some(handle.clone());
                                pending_relink_token = None;
                                let _ = tx.send(RelayFrame::Authenticated {
                                    relay_session_id: relay_session_id.clone(),
                                    handle: handle.clone(),
                                });
                                for envelope in queued_messages {
                                    tx.send(RelayFrame::Envelope { envelope })?;
                                }
                                for request in queued_requests {
                                    tx.send(RelayFrame::ContactRequest { request })?;
                                }
                                for receipt in queued_receipts {
                                    tx.send(RelayFrame::Receipt { receipt })?;
                                }
                                for cursor in queued_cursors {
                                    tx.send(RelayFrame::ReadCursor { cursor })?;
                                }
                            }
                            BindingDecision::Conflict {
                                relink_token,
                                existing_identity_fingerprint,
                                requested_identity_fingerprint,
                            } => {
                                pending_relink_token = Some(relink_token.clone());
                                state.write().await.pending_relink_channels.insert(relink_token.clone(), tx.clone());
                                let _ = tx.send(RelayFrame::BindingConflict {
                                    handle,
                                    device_id,
                                    existing_identity_fingerprint,
                                    requested_identity_fingerprint,
                                    relink_token,
                                    message: "binding conflict detected; request approval from an authenticated sibling device or rotate from the current device".into(),
                                });
                            }
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(RelayFrame::Error {
                            message: format!("auth failed: {error}"),
                        });
                    }
                }
            }
            RelayFrame::KeyRotationRequest {
                handle,
                device_id,
                current_identity_fingerprint,
                new_public_bundle_base64,
                new_identity_fingerprint,
            } => {
                let sender_handle = authenticated_handle.clone().ok_or_else(|| anyhow!("key rotation before auth"))?;
                let sender_device_id = announced_device_id.clone().unwrap_or_else(|| "unknown-device".to_string());
                if sender_handle != handle || sender_device_id != device_id {
                    tx.send(RelayFrame::Error {
                        message: "key rotation identity mismatch".into(),
                    })?;
                    continue;
                }
                let public_bundle_json = STANDARD_NO_PAD.decode(&new_public_bundle_base64)?;
                let public_bundle: PublicIdentityBundle = serde_json::from_slice(&public_bundle_json)
                    .context("rotation carried an invalid public bundle")?;
                if public_bundle.relay_handle != handle
                    || public_bundle.device_id != device_id
                    || public_bundle.identity_fingerprint != new_identity_fingerprint
                {
                    tx.send(RelayFrame::Error {
                        message: "rotation bundle does not match claimed handle/device/fingerprint".into(),
                    })?;
                    continue;
                }

                let old_identity_fingerprint = current_identity_fingerprint.clone();
                let clients = {
                    let mut state_guard = state.write().await;
                    state_guard.bindings.rotate_binding(
                        &handle,
                        &device_id,
                        &current_identity_fingerprint,
                        &new_identity_fingerprint,
                        &new_public_bundle_base64,
                    )?;
                    state_guard.clients.get(&handle).cloned().unwrap_or_default()
                };

                let frame = RelayFrame::KeyRotationApplied {
                    handle,
                    device_id,
                    old_identity_fingerprint,
                    new_identity_fingerprint,
                    rotated_at: now_ms(),
                };
                for (_, client_tx) in clients {
                    let _ = client_tx.send(frame.clone());
                }
            }
            RelayFrame::ApproveDeviceRelink {
                handle,
                device_id,
                relink_token,
            } => {
                let approver_handle = authenticated_handle.clone().ok_or_else(|| anyhow!("approve relink before auth"))?;
                let (old_identity_fingerprint, new_identity_fingerprint, same_handle_clients, pending_tx) = {
                    let mut state_guard = state.write().await;
                    let pending = state_guard
                        .bindings
                        .pending_relink(&relink_token)
                        .ok_or_else(|| anyhow!("unknown relink token"))?;
                    let old_identity_fingerprint = pending.existing_identity_fingerprint.clone();
                    let new_identity_fingerprint = pending.requested_identity_fingerprint.clone();
                    state_guard
                        .bindings
                        .approve_device_relink(&approver_handle, &handle, &device_id, &relink_token)?;
                    let same_handle_clients = state_guard.clients.get(&handle).cloned().unwrap_or_default();
                    let pending_tx = state_guard.pending_relink_channels.remove(&relink_token);
                    (
                        old_identity_fingerprint,
                        new_identity_fingerprint,
                        same_handle_clients,
                        pending_tx,
                    )
                };

                let frame = RelayFrame::DeviceRelinkApplied {
                    handle: handle.clone(),
                    device_id: device_id.clone(),
                    old_identity_fingerprint,
                    new_identity_fingerprint,
                    relink_token: relink_token.clone(),
                    relinked_at: now_ms(),
                };
                for (_, client_tx) in same_handle_clients {
                    let _ = client_tx.send(frame.clone());
                }
                if let Some(waiting_tx) = pending_tx {
                    let _ = waiting_tx.send(frame);
                }
            }
            RelayFrame::Publish { envelope } => {
                let sender = authenticated_handle.clone().ok_or_else(|| anyhow!("publish before auth"))?;
                if sender != envelope.sender_handle {
                    tx.send(RelayFrame::Error {
                        message: "sender handle mismatch".into(),
                    })?;
                    continue;
                }
                let already_seen = { state.read().await.delivered_message_ids.contains(&envelope.message_id) };
                if already_seen {
                    let _ = tx.send(RelayFrame::DeliveryAck {
                        message_id: envelope.message_id.clone(),
                        delivered_at: now_ms(),
                    });
                    continue;
                }
                let recipient_clients = { state.read().await.clients.get(&envelope.recipient_handle).cloned().unwrap_or_default() };
                {
                    let mut state_write = state.write().await;
                    bounded_push(
                        &mut state_write.message_history,
                        envelope.recipient_handle.clone(),
                        envelope.clone(),
                        MAX_HISTORY_PER_HANDLE,
                    );
                    bounded_insert(&mut state_write.delivered_message_ids, envelope.message_id.clone(), MAX_SEEN_IDS);
                }
                if recipient_clients.is_empty() {
                    bounded_push(
                        &mut state.write().await.queued_messages,
                        envelope.recipient_handle.clone(),
                        envelope.clone(),
                        MAX_QUEUE_PER_HANDLE,
                    );
                } else {
                    for (_, recipient_tx) in recipient_clients {
                        let _ = recipient_tx.send(RelayFrame::Envelope {
                            envelope: envelope.clone(),
                        });
                    }
                }
                let _ = tx.send(RelayFrame::DeliveryAck {
                    message_id: envelope.message_id.clone(),
                    delivered_at: now_ms(),
                });
            }
            RelayFrame::ContactRequest { request } => {
                let sender = authenticated_handle.clone().ok_or_else(|| anyhow!("contact request before auth"))?;
                if sender != request.sender_handle {
                    tx.send(RelayFrame::Error {
                        message: "contact sender handle mismatch".into(),
                    })?;
                    continue;
                }
                let recipient_clients = { state.read().await.clients.get(&request.recipient_handle).cloned().unwrap_or_default() };
                bounded_push(
                    &mut state.write().await.contact_request_history,
                    request.recipient_handle.clone(),
                    request.clone(),
                    MAX_HISTORY_PER_HANDLE,
                );
                if recipient_clients.is_empty() {
                    bounded_push(
                        &mut state.write().await.queued_contact_requests,
                        request.recipient_handle.clone(),
                        request.clone(),
                        MAX_QUEUE_PER_HANDLE,
                    );
                } else {
                    for (_, recipient_tx) in recipient_clients {
                        let _ = recipient_tx.send(RelayFrame::ContactRequest {
                            request: request.clone(),
                        });
                    }
                }
            }
            RelayFrame::Receipt { receipt } => {
                let recipient_handle = authenticated_handle.clone().ok_or_else(|| anyhow!("receipt before auth"))?;
                if recipient_handle != receipt.recipient_handle {
                    tx.send(RelayFrame::Error {
                        message: "receipt recipient handle mismatch".into(),
                    })?;
                    continue;
                }
                let skip = { state.read().await.seen_receipt_ids.contains(&receipt.receipt_id) };
                if skip {
                    continue;
                }
                let sender_clients = { state.read().await.clients.get(&receipt.sender_handle).cloned().unwrap_or_default() };
                {
                    let mut state_write = state.write().await;
                    bounded_insert(&mut state_write.seen_receipt_ids, receipt.receipt_id.clone(), MAX_SEEN_IDS);
                    bounded_push(
                        &mut state_write.receipt_history,
                        receipt.sender_handle.clone(),
                        receipt.clone(),
                        MAX_HISTORY_PER_HANDLE,
                    );
                }
                for (_, sender_tx) in sender_clients {
                    let _ = sender_tx.send(RelayFrame::Receipt {
                        receipt: receipt.clone(),
                    });
                }
            }
            RelayFrame::ReadCursor { cursor } => {
                let handle = authenticated_handle.clone().ok_or_else(|| anyhow!("read cursor before auth"))?;
                let device_id = announced_device_id.clone().unwrap_or_else(|| "unknown-device".to_string());
                if handle != cursor.handle || device_id != cursor.device_id {
                    tx.send(RelayFrame::Error {
                        message: "read cursor identity mismatch".into(),
                    })?;
                    continue;
                }
                let skip = { state.read().await.seen_read_cursor_ids.contains(&cursor.cursor_id) };
                if skip {
                    continue;
                }
                let (same_handle_clients, sender_handles) = {
                    let state_read = state.read().await;
                    let local_clients = state_read.clients.get(&cursor.handle).cloned().unwrap_or_default();
                    let senders = state_read
                        .message_history
                        .get(&cursor.handle)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|message| {
                            message.conversation_id == cursor.conversation_id && message.sent_at <= cursor.read_through_timestamp
                        })
                        .map(|message| message.sender_handle)
                        .collect::<HashSet<_>>();
                    (local_clients, senders)
                };
                {
                    let mut state_write = state.write().await;
                    bounded_insert(&mut state_write.seen_read_cursor_ids, cursor.cursor_id.clone(), MAX_SEEN_IDS);
                    bounded_push(
                        &mut state_write.read_cursor_history,
                        cursor.handle.clone(),
                        cursor.clone(),
                        MAX_HISTORY_PER_HANDLE,
                    );
                    for sender_handle in &sender_handles {
                        bounded_push(
                            &mut state_write.read_cursor_history,
                            sender_handle.clone(),
                            cursor.clone(),
                            MAX_HISTORY_PER_HANDLE,
                        );
                    }
                }
                for (other_device_id, local_tx) in same_handle_clients {
                    if other_device_id != cursor.device_id {
                        let _ = local_tx.send(RelayFrame::ReadCursor {
                            cursor: cursor.clone(),
                        });
                    }
                }
                for sender_handle in sender_handles {
                    let sender_clients = { state.read().await.clients.get(&sender_handle).cloned().unwrap_or_default() };
                    for (_, sender_tx) in sender_clients {
                        let _ = sender_tx.send(RelayFrame::ReadCursor {
                            cursor: cursor.clone(),
                        });
                    }
                }
            }
            RelayFrame::PeerBundleRequest { peer_handle, device_id } => {
                let bundles = state
                    .read()
                    .await
                    .bindings
                    .bindings_for_handle(&peer_handle, device_id.as_deref());
                let first_bundle = bundles.first().map(|entry| entry.public_bundle_base64.clone());
                let _ = tx.send(RelayFrame::PeerBundleResponse {
                    peer_handle,
                    public_bundle_base64: first_bundle,
                    bundles,
                });
            }
            RelayFrame::HistorySyncRequest { since } => {
                let handle = authenticated_handle.clone().ok_or_else(|| anyhow!("history sync before auth"))?;
                let (envelopes, contact_requests, receipts, read_cursors) = {
                    let state_read = state.read().await;
                    (
                        state_read
                            .message_history
                            .get(&handle)
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|item| item.sent_at > since)
                            .collect::<Vec<_>>(),
                        state_read
                            .contact_request_history
                            .get(&handle)
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|item| item.sent_at > since)
                            .collect::<Vec<_>>(),
                        state_read
                            .receipt_history
                            .get(&handle)
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|item| item.recorded_at > since)
                            .collect::<Vec<_>>(),
                        state_read
                            .read_cursor_history
                            .get(&handle)
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|item| item.recorded_at > since)
                            .collect::<Vec<_>>(),
                    )
                };
                let _ = tx.send(RelayFrame::HistorySyncResponse {
                    relay_session_id: relay_session_id.clone(),
                    synced_until: now_ms(),
                    envelopes,
                    contact_requests,
                    receipts,
                    read_cursors,
                });
            }
            RelayFrame::Signaling { from_handle, to_handle, signal_type, payload, sent_at } => {
                let handle = authenticated_handle.clone().ok_or_else(|| anyhow!("signaling before auth"))?;
                if from_handle != handle {
                    let _ = tx.send(RelayFrame::Error { message: "signaling from_handle does not match authenticated handle".into() });
                    continue;
                }
                let recipients = { state.read().await.clients.get(&to_handle).cloned().unwrap_or_default() };
                if recipients.is_empty() {
                    tracing::debug!(from = %from_handle, to = %to_handle, "signaling target offline");
                }
                for (_, recipient_tx) in recipients {
                    let _ = recipient_tx.send(RelayFrame::Signaling {
                        from_handle: from_handle.clone(),
                        to_handle: to_handle.clone(),
                        signal_type: signal_type.clone(),
                        payload: payload.clone(),
                        sent_at,
                    });
                }
            }
            RelayFrame::PeerBundleResponse { .. }
            | RelayFrame::Challenge { .. }
            | RelayFrame::Authenticated { .. }
            | RelayFrame::BindingConflict { .. }
            | RelayFrame::KeyRotationApplied { .. }
            | RelayFrame::DeviceRelinkApplied { .. }
            | RelayFrame::Envelope { .. }
            | RelayFrame::DeliveryAck { .. }
            | RelayFrame::HistorySyncResponse { .. }
            | RelayFrame::Error { .. } => {
                let _ = tx.send(RelayFrame::Error {
                    message: "client sent invalid frame for server side".into(),
                });
            }
        }
    }

    if let Some(token) = pending_relink_token {
        state.write().await.pending_relink_channels.remove(&token);
    }
    if let Some(handle) = authenticated_handle {
        if let Some(device_id) = announced_device_id {
            let mut state_write = state.write().await;
            if let Some(device_map) = state_write.clients.get_mut(&handle) {
                device_map.remove(&device_id);
                if device_map.is_empty() {
                    state_write.clients.remove(&handle);
                }
            }
        }
    }
    writer.abort();
    Ok(())
}


fn load_tls_acceptor() -> Result<Option<TlsAcceptor>> {
    let cert_path = std::env::var("QUBEE_RELAY_TLS_CERT_PATH").ok();
    let key_path = std::env::var("QUBEE_RELAY_TLS_KEY_PATH").ok();
    match (cert_path, key_path) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(anyhow!("both QUBEE_RELAY_TLS_CERT_PATH and QUBEE_RELAY_TLS_KEY_PATH must be set")),
        (Some(cert_path), Some(key_path)) => {
            let certs = load_certificates(&cert_path)?;
            let key = load_private_key(&key_path)?;
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .context("failed to configure TLS certificate")?;
            Ok(Some(TlsAcceptor::from(Arc::new(config))))
        }
    }
}

fn load_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path).with_context(|| format!("failed to open TLS certificate at {path}"))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(anyhow!("no TLS certificates found in {path}"));
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path).with_context(|| format!("failed to open TLS key at {path}"))?;
    let mut reader = BufReader::new(file);
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader).next() {
        return Ok(key?.into());
    }
    let file = std::fs::File::open(path).with_context(|| format!("failed to re-open TLS key at {path}"))?;
    let mut reader = BufReader::new(file);
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader).next() {
        return Ok(key?.into());
    }
    let file = std::fs::File::open(path).with_context(|| format!("failed to re-open TLS key at {path}"))?;
    let mut reader = BufReader::new(file);
    if let Some(key) = rustls_pemfile::ec_private_keys(&mut reader).next() {
        return Ok(key?.into());
    }
    Err(anyhow!("no supported private key found in {path}"))
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}
