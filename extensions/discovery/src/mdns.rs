//! mDNS / DNS-SD backend (§3) — the v1 same-network backend. Native-only:
//! browsers cannot speak multicast UDP (§3.4), so this module is compiled out
//! on wasm32.
//!
//! Built on `mdns-sd` (RFC 6762/6763 compliant), so it interoperates on the
//! wire with any cohort impl that pins the same §3.2 constants — the DNS-SD
//! service-type and TXT-key schema, which live as normative constants in
//! [`crate`]. The packet bytes are the cross-impl convergence surface; matching
//! §3.2 closes the *silent* non-discovery class (Go and Rust never seeing each
//! other on the LAN with no error to catch).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use entity_ecf::{integer, text, Value};
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::backend::{AnnounceParams, DiscoveryBackend, Observation};
use crate::{
    DiscoveryError, BACKEND_MDNS, MDNS_SERVICE_TYPE, MDNS_VERSION, TXT_KEY_DISPLAY_NAME,
    TXT_KEY_PEER_ID_HINT, TXT_KEY_PROFILE_REF, TXT_KEY_PROTO, TXT_KEY_VERSION,
};

/// Default `:scan` collection window — how long a snapshot browse listens for
/// query responses before returning (§3.0). Conservative; operator-tunable.
pub const DEFAULT_SCAN_WINDOW: Duration = Duration::from_millis(1500);

/// mDNS backend over a [`ServiceDaemon`] (its own background thread + multicast
/// socket). The daemon is created **lazily** on first scan/announce, so merely
/// building a peer with discovery enabled costs nothing — the socket opens only
/// when discovery is actually used. `ServiceDaemon` is a cheap cloneable handle.
pub struct MdnsBackend {
    daemon: Mutex<Option<ServiceDaemon>>,
    scan_window: Duration,
    /// `profile_ref → registered service fullname`, for `:announce-stop`.
    announced: Mutex<HashMap<String, String>>,
}

impl Default for MdnsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MdnsBackend {
    /// Construct the backend without opening any socket (the daemon is created
    /// on first use). Infallible — socket-open errors surface at call time as
    /// `DiscoveryError::Backend`, never a peer-bootstrap failure.
    pub fn new() -> Self {
        Self::with_scan_window(DEFAULT_SCAN_WINDOW)
    }

    pub fn with_scan_window(scan_window: Duration) -> Self {
        Self {
            daemon: Mutex::new(None),
            scan_window,
            announced: Mutex::new(HashMap::new()),
        }
    }

    /// Lazily create (once) and return a handle to the mDNS daemon.
    fn daemon(&self) -> Result<ServiceDaemon, DiscoveryError> {
        let mut guard = self.daemon.lock().expect("mdns daemon mutex poisoned");
        if let Some(d) = guard.as_ref() {
            return Ok(d.clone());
        }
        let d = ServiceDaemon::new().map_err(|e| DiscoveryError::Backend(e.to_string()))?;
        *guard = Some(d.clone());
        Ok(d)
    }

    /// Build a `CandidateData`-ready [`Observation`] from a resolved service.
    /// Addresses are sorted so `endpoint_hint` (and thus the candidate's
    /// `content_hash`) is stable across runs despite the unordered address set.
    fn observation_from(info: &ResolvedService) -> Observation {
        let mut addrs: Vec<String> = info.get_addresses().iter().map(|a| a.to_string()).collect();
        addrs.sort();

        let mut hint: Vec<(Value, Value)> = vec![
            (
                text("addrs"),
                Value::Array(addrs.into_iter().map(text).collect()),
            ),
            (text("port"), integer(i64::from(info.get_port()))),
        ];
        if let Some(p) = info.get_property_val_str(TXT_KEY_PROFILE_REF) {
            hint.push((text(TXT_KEY_PROFILE_REF), text(p)));
        }
        if let Some(p) = info.get_property_val_str(TXT_KEY_PROTO) {
            hint.push((text(TXT_KEY_PROTO), text(p)));
        }
        if let Some(n) = info.get_property_val_str(TXT_KEY_DISPLAY_NAME) {
            hint.push((text(TXT_KEY_DISPLAY_NAME), text(n)));
        }

        Observation {
            key: info.get_fullname().to_string(),
            peer_id: info
                .get_property_val_str(TXT_KEY_PEER_ID_HINT)
                .map(|s| s.to_string()),
            endpoint_hint: Value::Map(hint),
        }
    }
}

#[async_trait::async_trait]
impl DiscoveryBackend for MdnsBackend {
    fn name(&self) -> &str {
        BACKEND_MDNS
    }

    async fn scan(&self, _filter: Option<Value>) -> Result<Vec<Observation>, DiscoveryError> {
        // §3.3: an unparseable filter would surface as an error here; v1's mDNS
        // filter is opaque/ignored, so any filter is accepted and we browse
        // unfiltered. A genuinely empty LAN returns Ok(vec![]), never an error.
        let daemon = self.daemon()?;
        let recv = daemon
            .browse(MDNS_SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Backend(e.to_string()))?;

        // Collect resolved services until the snapshot window elapses, deduped
        // by fullname (last-resolved wins).
        let mut seen: HashMap<String, Observation> = HashMap::new();
        let deadline = tokio::time::Instant::now() + self.scan_window;
        loop {
            match tokio::time::timeout_at(deadline, recv.recv_async()).await {
                Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                    let obs = Self::observation_from(&info);
                    seen.insert(obs.key.clone(), obs);
                }
                Ok(Ok(_)) => {} // SearchStarted / ServiceFound / Removed — ignored for snapshot
                Ok(Err(_)) => break, // channel disconnected
                Err(_) => break,     // window elapsed
            }
        }
        let _ = daemon.stop_browse(MDNS_SERVICE_TYPE);

        let mut out: Vec<Observation> = seen.into_values().collect();
        out.sort_by(|a, b| a.key.cmp(&b.key)); // deterministic snapshot order
        Ok(out)
    }

    async fn announce(&self, params: &AnnounceParams) -> Result<(), DiscoveryError> {
        // Instance label: peer-id when known, else the profile-ref. mDNS
        // instance names are human-labels; uniqueness on the LAN is the peer's.
        let instance = params
            .peer_id
            .as_deref()
            .unwrap_or(&params.profile_ref)
            .to_string();
        let host_name = format!("{}.local.", sanitize_host(&instance));

        // §3.2 TXT schema: version + profile_ref MUST-present; peer_id_hint
        // MUST-present unless anonymous-pre-IDENTIFY; proto/display_name optional.
        let mut props: HashMap<String, String> = HashMap::new();
        props.insert(TXT_KEY_VERSION.to_string(), MDNS_VERSION.to_string());
        props.insert(TXT_KEY_PROFILE_REF.to_string(), params.profile_ref.clone());
        if let Some(p) = &params.peer_id {
            props.insert(TXT_KEY_PEER_ID_HINT.to_string(), p.clone());
        }
        if let Some(p) = &params.proto {
            props.insert(TXT_KEY_PROTO.to_string(), p.clone());
        }
        if let Some(n) = &params.display_name {
            props.insert(TXT_KEY_DISPLAY_NAME.to_string(), n.clone());
        }

        // Empty ip + enable_addr_auto: the daemon fills in (and tracks changes
        // to) the host's addresses, so the SRV/A records advertise real IPs.
        let info = ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &instance,
            &host_name,
            "",
            params.port,
            props,
        )
        .map_err(|e| DiscoveryError::Backend(e.to_string()))?
        .enable_addr_auto();

        let fullname = info.get_fullname().to_string();
        self.daemon()?
            .register(info)
            .map_err(|e| DiscoveryError::Backend(e.to_string()))?;
        self.announced
            .lock()
            .expect("announce map poisoned")
            .insert(params.profile_ref.clone(), fullname);
        Ok(())
    }

    async fn announce_stop(&self, profile_ref: &str) -> Result<(), DiscoveryError> {
        let fullname = self
            .announced
            .lock()
            .expect("announce map poisoned")
            .remove(profile_ref);
        let Some(fullname) = fullname else {
            // No active session for this profile_ref — idempotent stop.
            return Ok(());
        };
        self.daemon()?
            .unregister(&fullname)
            .map_err(|e| DiscoveryError::Backend(e.to_string()))?;
        Ok(())
    }
}

/// mDNS host labels may not contain dots (each dot is a label separator) or
/// spaces; map anything outside `[A-Za-z0-9-]` to `-`.
fn sanitize_host(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .collect()
}
