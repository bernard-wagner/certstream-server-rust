//! Optional durable output to NATS JetStream.
//!
//! The use this exists for: "I took my analysis service down for ten minutes;
//! when it comes back it should carry on from where it stopped." A WebSocket
//! subscriber cannot do that — a stream it is not connected to is a stream it
//! misses. A JetStream consumer can.
//!
//! Publishing alone would buy little, so three things go with it:
//!
//! * **The saved position follows acknowledgements, not reads.** A watcher
//!   that has read to entry N but had only entries up to M acknowledged
//!   persists M, so a restart re-reads `M..N` rather than skipping it.
//!   [`AckTracker`] keeps those two positions apart, and advances only over a
//!   contiguous prefix — an index that produced no record has to be settled
//!   explicitly or it pins the position where it is.
//!
//! * **Republished records carry a stable identity.** The `Nats-Msg-Id` is
//!   `<log_id>:<index>`, the same address the v2 output uses, so a re-read
//!   after a restart is deduplicated by the server inside its duplicate
//!   window instead of appearing twice.
//!
//! * **A full stream has a stated behaviour.** The stream is created with
//!   `discard: new`, so it rejects the write rather than deleting records a
//!   stopped consumer had not read. `on_full` decides what happens next:
//!   `block` retries the record until the server stores it and lets the queue
//!   behind it push back on ingest, `drop` gives up on the record and settles
//!   its index so the position can move past it.
//!
//! What this does **not** provide: delivery is at-least-once within the
//! server's own reading, not exactly-once end to end. A record `drop` mode
//! gave up on is gone, and cross-log duplicates of one certificate are
//! published as the separate log records they are.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream::{self, stream::DiscardPolicy};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tokio::time::Instant;

use crate::config::{NatsConfig, NatsOnFull};

/// One record on its way to JetStream.
pub struct Record {
    /// Log the entry came from, as a state-file key.
    pub log_url: Arc<str>,
    /// Stable identity: `<log_id>:<index>`, or `<url>:<index>` for a log
    /// whose list entry carries no id.
    pub msg_id: String,
    /// Where in the log this entry sits. Drives the acknowledged position.
    pub index: u64,
    pub subject: String,
    pub payload: bytes::Bytes,
}

/// Per-log gap between what has been read and what JetStream has confirmed.
///
/// The saved position must be the *contiguous* acknowledged prefix, not the
/// highest acknowledged index: acknowledgements can land out of order, and
/// persisting a high index with a hole below it would skip the hole forever.
#[derive(Default)]
pub struct AckTracker {
    logs: Mutex<HashMap<Arc<str>, LogAcks>>,
}

#[derive(Default)]
struct LogAcks {
    /// Everything strictly below this is acknowledged.
    contiguous: u64,
    /// Acknowledged indexes at or above `contiguous`, waiting on the gap
    /// below them to close.
    ahead: std::collections::BTreeSet<u64>,
    started: bool,
}

impl AckTracker {
    /// Anchor a log's acknowledged position, from the state file at startup
    /// or from a watcher's starting index the first time it reads a log with
    /// no saved position.
    ///
    /// Without an anchor the contiguous prefix would start at 0 while the
    /// watcher publishes from the log's head, so nothing would ever close the
    /// gap and every save would write index 0 — rewinding the log to the
    /// beginning on the next restart. Only the first anchor counts; a later
    /// call cannot move a log that is already running.
    pub fn resume_at(&self, log_url: &str, index: u64) {
        let mut logs = self.logs.lock();
        let entry = logs.entry(Arc::from(log_url)).or_default();
        if !entry.started {
            entry.contiguous = index;
            entry.started = true;
        }
    }

    /// An index JetStream has stored.
    pub fn record_ack(&self, log_url: &Arc<str>, index: u64) {
        self.settle(log_url, index);
    }

    /// An index that will never be published, and so must not hold the
    /// position back.
    ///
    /// A watcher does not publish every index it reads: an entry it cannot
    /// parse produces no record. Without this the contiguous prefix would stop
    /// at the first such index forever, pinning the saved position and letting
    /// every later acknowledgement pile up unresolved.
    pub fn record_skipped(&self, log_url: &Arc<str>, index: u64) {
        self.settle(log_url, index);
    }

    fn settle(&self, log_url: &Arc<str>, index: u64) {
        let mut logs = self.logs.lock();
        let entry = logs.entry(Arc::clone(log_url)).or_default();
        entry.started = true;

        if index < entry.contiguous {
            return;
        }
        entry.ahead.insert(index);
        while entry.ahead.remove(&entry.contiguous) {
            entry.contiguous += 1;
        }
    }

    /// The position it is safe to persist for this log.
    pub fn acked_index(&self, log_url: &str) -> Option<u64> {
        let logs = self.logs.lock();
        logs.get(log_url)
            .filter(|acks| acks.started)
            .map(|acks| acks.contiguous)
    }

    pub fn pending(&self) -> usize {
        self.logs.lock().values().map(|a| a.ahead.len()).sum()
    }
}

/// Handle the watchers hold. Cheap to clone; the work happens in the
/// publisher task.
#[derive(Clone)]
pub struct NatsSink {
    tx: mpsc::Sender<QueuedRecord>,
    on_full: NatsOnFull,
    pub acks: Arc<AckTracker>,
    metrics: NatsMetrics,
}

struct QueuedRecord {
    record: Record,
    enqueued_at: Instant,
}

#[derive(Clone)]
struct NatsMetrics {
    enqueue: crate::telemetry::Timing,
    publish: crate::telemetry::Timing,
    send: crate::telemetry::Timing,
    ack: crate::telemetry::Timing,
    retry: crate::telemetry::Timing,
    residence: metrics::Histogram,
    queue_depth: metrics::Gauge,
}

impl NatsMetrics {
    fn new(capacity: usize) -> Self {
        metrics::gauge!("certstream_nats_queue_capacity").set(capacity as f64);
        let queue_depth = metrics::gauge!("certstream_nats_queue_depth");
        queue_depth.set(0.0);
        let timing = |name, active| crate::telemetry::Timing::new(name, active, &[]);
        Self {
            enqueue: timing("certstream_nats_enqueue_seconds", "certstream_nats_enqueue_active"),
            publish: timing("certstream_nats_publish_seconds", "certstream_nats_publish_active"),
            send: timing("certstream_nats_send_seconds", "certstream_nats_send_active"),
            ack: timing("certstream_nats_ack_seconds", "certstream_nats_ack_active"),
            retry: timing("certstream_nats_retry_wait_seconds", "certstream_nats_retry_wait_active"),
            residence: metrics::histogram!("certstream_nats_queue_residence_seconds"),
            queue_depth,
        }
    }
}

// Sample independently of publish ACKs, so a stalled publisher cannot hide a
// full queue. A weak sender does not keep the channel open after watchers exit.
fn sample_queue(
    sender: mpsc::WeakSender<QueuedRecord>,
    depth: metrics::Gauge,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    let Some(sender) = sender.upgrade() else { break };
                    depth.set((sender.max_capacity() - sender.capacity()) as f64);
                }
            }
        }
        depth.set(0.0);
    });
}

impl NatsSink {
    /// Queue a record. Returns false when the record was dropped rather than
    /// queued, which only happens under `on_full: drop`.
    ///
    /// Under `block` this waits for room. That back-pressure is the point: the
    /// publisher retries the record at the head of the queue until the server
    /// stores it, so a queue that fills is ingest being told to slow down
    /// rather than records being lost.
    pub async fn publish(&self, record: Record) -> bool {
        let _timer = self.metrics.enqueue.start();
        match self.on_full {
            NatsOnFull::Block => match self.tx.reserve().await {
                Ok(permit) => {
                    permit.send(QueuedRecord { record, enqueued_at: Instant::now() });
                    true
                }
                Err(_) => false,
            },
            NatsOnFull::Drop => match self.tx.try_reserve() {
                Ok(permit) => {
                    permit.send(QueuedRecord { record, enqueued_at: Instant::now() });
                    true
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    metrics::counter!("certstream_nats_dropped_total").increment(1);
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            },
        }
    }
}

/// Connect, ensure the stream exists, and start the publisher task.
pub async fn start(
    config: &NatsConfig,
    cancel: CancellationToken,
) -> Result<NatsSink, async_nats::Error> {
    let client = async_nats::ConnectOptions::new()
        .name(concat!("certstream-server-rust/", env!("CARGO_PKG_VERSION")))
        .connect(&config.url)
        .await?;
    let context = jetstream::new(client);

    let stream_config = jetstream::stream::Config {
        name: config.stream.clone(),
        subjects: vec![format!("{}.>", config.subject_prefix)],
        max_bytes: config.max_bytes,
        // The whole point of the durable path: a full stream must refuse the
        // write so the publisher finds out, not quietly delete the oldest
        // records a stopped consumer had not read yet.
        discard: DiscardPolicy::New,
        duplicate_window: Duration::from_secs(config.duplicate_window_secs),
        ..Default::default()
    };
    let stream = context.get_or_create_stream(stream_config).await?;
    let info = stream.cached_info();
    info!(
        stream = %config.stream,
        subject = %format!("{}.>", config.subject_prefix),
        max_bytes = config.max_bytes,
        duplicate_window_secs = config.duplicate_window_secs,
        messages = info.state.messages,
        "NATS JetStream output enabled"
    );

    let (tx, rx) = mpsc::channel(config.queue_depth);
    let acks = Arc::new(AckTracker::default());
    let metrics = NatsMetrics::new(config.queue_depth);
    sample_queue(tx.downgrade(), metrics.queue_depth.clone(), cancel.clone());
    spawn_publisher(context, rx, Arc::clone(&acks), config.clone(), cancel, metrics.clone());

    Ok(NatsSink {
        tx,
        on_full: config.on_full,
        acks,
        metrics,
    })
}

fn spawn_publisher(
    context: jetstream::Context,
    mut rx: mpsc::Receiver<QueuedRecord>,
    acks: Arc<AckTracker>,
    config: NatsConfig,
    cancel: CancellationToken,
    metrics: NatsMetrics,
) {
    tokio::spawn(async move {
        let timeout = Duration::from_secs(config.publish_timeout_secs);
        loop {
            let record = tokio::select! {
                _ = cancel.cancelled() => break,
                record = rx.recv() => match record {
                    Some(r) => r,
                    None => break,
                },
            };
            metrics.queue_depth.set(rx.len() as f64);
            metrics.residence.record(record.enqueued_at.elapsed().as_secs_f64());
            let record = record.record;

            let mut attempt: u32 = 0;
            loop {
                let result = {
                    let _timer = metrics.publish.start();
                    store(&context, &record, timeout, &metrics).await
                };
                match result {
                    Ok(()) => {
                        acks.record_ack(&record.log_url, record.index);
                        metrics::counter!("certstream_nats_published_total").increment(1);
                        break;
                    }
                    Err(reason) => {
                        metrics::counter!("certstream_nats_publish_failures_total").increment(1);
                        if cancel.is_cancelled() {
                            break;
                        }
                        if config.on_full == NatsOnFull::Drop {
                            warn!(msg_id = %record.msg_id, reason, "record dropped");
                            metrics::counter!("certstream_nats_dropped_total").increment(1);
                            // The index still has to settle, or it pins the
                            // saved position at a record this mode chose not
                            // to keep.
                            acks.record_skipped(&record.log_url, record.index);
                            break;
                        }

                        // `block` means this record is retried until it is
                        // stored. The queue behind it fills, and that
                        // back-pressure reaches ingest — which is the point:
                        // giving up here would leave a hole no restart can
                        // see, because the saved position never passes it.
                        attempt = attempt.saturating_add(1);
                        let backoff = retry_delay(attempt);
                        warn!(
                            msg_id = %record.msg_id,
                            reason,
                            attempt,
                            retry_in_ms = backoff.as_millis() as u64,
                            "JetStream did not store the record; retrying"
                        );
                        let _timer = metrics.retry.start();
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                    }
                }
            }
        }
        metrics.queue_depth.set(0.0);
        info!(pending = acks.pending(), "NATS publisher stopped");
    });
}

/// One publish attempt: send, then wait for the server to say it stored it.
async fn store(
    context: &jetstream::Context,
    record: &Record,
    timeout: Duration,
    metrics: &NatsMetrics,
) -> Result<(), String> {
    let mut headers = async_nats::HeaderMap::new();
    // Stable across republishes, so a re-read after a restart is the same
    // message to the server rather than a second one.
    headers.insert("Nats-Msg-Id", record.msg_id.as_str());

    let future = {
        let _timer = metrics.send.start();
        context
            .publish_with_headers(record.subject.clone(), headers, record.payload.clone())
            .await
            .map_err(|e| e.to_string())?
    };

    let _timer = metrics.ack.start();
    match tokio::time::timeout(timeout, future.into_future()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("ack timed out".to_string()),
    }
}

/// Exponential backoff, capped. A full stream or a broker outage lasts
/// minutes, not milliseconds, and retrying faster than that only burns the
/// connection.
fn retry_delay(attempt: u32) -> Duration {
    const BASE_MS: u64 = 250;
    const MAX_MS: u64 = 30_000;
    Duration::from_millis(BASE_MS.saturating_mul(1 << attempt.min(7)).min(MAX_MS))
}

/// Log an unrecoverable startup problem in the same shape as the rest of the
/// server's fatal paths.
pub fn report_start_failure(e: &async_nats::Error) {
    error!(error = %e, "could not start the NATS JetStream output");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::tests::{recorded, runtime, value};

    fn test_record(index: u64) -> Record {
        Record {
            log_url: Arc::from("https://test.invalid/"),
            msg_id: format!("test:{index}"),
            index,
            subject: "test.log".to_owned(),
            payload: bytes::Bytes::from_static(b"{}"),
        }
    }

    fn test_sink(on_full: NatsOnFull) -> (NatsSink, mpsc::Receiver<QueuedRecord>) {
        let (tx, rx) = mpsc::channel(1);
        (NatsSink {
            tx, on_full, acks: Arc::new(AckTracker::default()),
            metrics: NatsMetrics::new(1),
        }, rx)
    }

    #[test]
    fn full_queue_wait_is_measured_and_cancellation_preserves_fifo() {
        let snapshot = recorded(|handle| runtime().block_on(async {
            let (sink, mut rx) = test_sink(NatsOnFull::Block);
            let cancel = CancellationToken::new();
            sample_queue(sink.tx.downgrade(), sink.metrics.queue_depth.clone(), cancel.clone());
            assert!(sink.publish(test_record(0)).await);
            assert!(tokio::time::timeout(Duration::from_millis(20), sink.publish(test_record(1))).await.is_err());
            let current = handle.render();
            assert_eq!(value(&current, "certstream_nats_queue_depth", &[]), 1.0);
            assert_eq!(value(&current, "certstream_nats_enqueue_active", &[]), 0.0);
            assert!(value(&current, "certstream_nats_enqueue_seconds_sum", &[]) >= 0.01);
            assert_eq!(rx.recv().await.unwrap().record.index, 0);
            assert!(rx.try_recv().is_err(), "cancelled enqueue must not insert a record");
            assert!(sink.publish(test_record(2)).await);
            assert_eq!(rx.recv().await.unwrap().record.index, 2);
            drop(sink);
            assert!(rx.recv().await.is_none(), "queue sampler must not keep the sender alive");
            cancel.cancel();
            tokio::task::yield_now().await;
        }));
        assert_eq!(value(&snapshot, "certstream_nats_queue_depth", &[]), 0.0);
        assert_eq!(value(&snapshot, "certstream_nats_enqueue_seconds_count", &[]), 3.0);
        assert!(snapshot.contains("certstream_nats_enqueue_seconds_bucket{"));
    }

    #[test]
    fn drop_mode_counts_full_queue_without_waiting_or_reordering() {
        let snapshot = recorded(|_| runtime().block_on(async {
            let (sink, mut rx) = test_sink(NatsOnFull::Drop);
            assert!(sink.publish(test_record(0)).await);
            assert!(!sink.publish(test_record(1)).await);
            assert_eq!(rx.recv().await.unwrap().record.index, 0);
            assert!(rx.try_recv().is_err());
        }));
        assert_eq!(value(&snapshot, "certstream_nats_dropped_total", &[]), 1.0);
        assert_eq!(value(&snapshot, "certstream_nats_enqueue_active", &[]), 0.0);
        assert_eq!(value(&snapshot, "certstream_nats_enqueue_seconds_count", &[]), 2.0);
    }

    #[test]
    fn closed_publisher_channel_returns_false_in_both_modes() {
        for mode in [NatsOnFull::Block, NatsOnFull::Drop] {
            let snapshot = recorded(|_| runtime().block_on(async {
                let (sink, rx) = test_sink(mode);
                drop(rx);
                assert!(!sink.publish(test_record(0)).await);
            }));
            assert_eq!(value(&snapshot, "certstream_nats_enqueue_active", &[]), 0.0);
        }
    }

    // A minimal loopback NATS peer that delays the publish ACK. It exercises
    // the real async-nats client and store() path without a broker or CT traffic.
    async fn delayed_ack_peer(delay: Duration) -> jetstream::Context {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            writer.write_all(b"INFO {\"server_id\":\"test\",\"version\":\"2.12.0\",\"headers\":true,\"proto\":1,\"max_payload\":1048576}\r\n").await.unwrap();
            let mut subscriptions: Vec<(String, String)> = Vec::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 { break; }
                let parts: Vec<&str> = line.split_whitespace().collect();
                match parts.as_slice() {
                    ["PING"] => { writer.write_all(b"PONG\r\n").await.unwrap(); }
                    ["SUB", subject, sid] => subscriptions.push(((*subject).to_owned(), (*sid).to_owned())),
                    ["HPUB", _, reply, _, length] => {
                        let mut payload = vec![0; length.parse::<usize>().unwrap() + 2];
                        reader.read_exact(&mut payload).await.unwrap();
                        let sid = &subscriptions.iter().find(|(subject, _)| reply.starts_with(subject.trim_end_matches('*'))).unwrap().1;
                        tokio::time::sleep(delay).await;
                        let ack = r#"{"stream":"TEST","seq":1,"duplicate":false}"#;
                        let message = format!("MSG {reply} {sid} {}\r\n{ack}\r\n", ack.len());
                        if writer.write_all(message.as_bytes()).await.is_err() { break; }
                    }
                    _ => {}
                }
            }
        });
        let client = async_nats::connect(format!("nats://{address}")).await.unwrap();
        jetstream::new(client)
    }

    #[test]
    fn durable_ack_wait_is_measured_separately_from_submission() {
        let snapshot = recorded(|_| runtime().block_on(async {
            let context = delayed_ack_peer(Duration::from_millis(40)).await;
            let metrics = NatsMetrics::new(1);
            let _timer = metrics.publish.start();
            tokio::time::timeout(Duration::from_secs(3), store(&context, &test_record(0), Duration::from_secs(1), &metrics)).await.unwrap().unwrap();
        }));
        assert!(value(&snapshot, "certstream_nats_ack_seconds_sum", &[]) >= 0.02);
        for stage in ["publish", "send", "ack"] {
            assert_eq!(value(&snapshot, &format!("certstream_nats_{stage}_seconds_count"), &[]), 1.0);
            assert_eq!(value(&snapshot, &format!("certstream_nats_{stage}_active"), &[]), 0.0);
        }
    }

    #[test]
    fn durable_ack_timeout_is_measured_and_still_returns_an_error() {
        let snapshot = recorded(|_| runtime().block_on(async {
            let context = delayed_ack_peer(Duration::from_secs(30)).await;
            let metrics = NatsMetrics::new(1);
            let result = tokio::time::timeout(Duration::from_secs(3), store(&context, &test_record(0), Duration::from_millis(20), &metrics)).await.unwrap();
            assert_eq!(result.unwrap_err(), "ack timed out");
        }));
        assert!(value(&snapshot, "certstream_nats_ack_seconds_sum", &[]) >= 0.01);
        assert_eq!(value(&snapshot, "certstream_nats_ack_active", &[]), 0.0);
    }

    fn tracker_with(url: &str, resume: u64) -> (AckTracker, Arc<str>) {
        let tracker = AckTracker::default();
        tracker.resume_at(url, resume);
        (tracker, Arc::from(url))
    }

    /// The property the whole module exists for: what gets saved is what was
    /// acknowledged, not what was read.
    #[test]
    fn the_acked_position_is_the_contiguous_prefix() {
        let (tracker, url) = tracker_with("https://log.example", 0);

        for index in 0..5 {
            tracker.record_ack(&url, index);
        }
        assert_eq!(tracker.acked_index("https://log.example"), Some(5));
    }

    /// Acks land out of order. Persisting the highest one would step over the
    /// hole below it, and the hole would never be re-read.
    #[test]
    fn a_hole_holds_the_position_back_until_it_closes() {
        let (tracker, url) = tracker_with("https://log.example", 0);

        tracker.record_ack(&url, 0);
        tracker.record_ack(&url, 1);
        tracker.record_ack(&url, 3);
        tracker.record_ack(&url, 4);
        assert_eq!(
            tracker.acked_index("https://log.example"),
            Some(2),
            "entry 2 is unacknowledged; the position must not pass it"
        );
        assert_eq!(tracker.pending(), 2);

        tracker.record_ack(&url, 2);
        assert_eq!(tracker.acked_index("https://log.example"), Some(5));
        assert_eq!(tracker.pending(), 0);
    }

    /// Without the anchor, a log read from its head would never close the gap
    /// down to zero, and every save would write index 0.
    #[test]
    fn a_resumed_log_starts_from_its_saved_position() {
        let (tracker, url) = tracker_with("https://log.example", 1_000);
        assert_eq!(tracker.acked_index("https://log.example"), Some(1000));

        tracker.record_ack(&url, 1000);
        tracker.record_ack(&url, 1001);
        assert_eq!(tracker.acked_index("https://log.example"), Some(1002));

        // A late ack from below the resume point changes nothing.
        tracker.record_ack(&url, 12);
        assert_eq!(tracker.acked_index("https://log.example"), Some(1002));
    }

    #[test]
    fn resuming_twice_does_not_move_a_log_that_is_already_running() {
        let (tracker, url) = tracker_with("https://log.example", 100);
        tracker.record_ack(&url, 100);
        tracker.resume_at("https://log.example", 5);
        assert_eq!(tracker.acked_index("https://log.example"), Some(101));
    }

    #[test]
    fn a_log_with_no_acks_and_no_resume_has_no_position() {
        let tracker = AckTracker::default();
        assert_eq!(tracker.acked_index("https://never-seen.example"), None);
    }

    /// A watcher starting a log with no saved position anchors at its own
    /// starting index. Acknowledging from there must advance the position
    /// rather than leave it pinned at zero.
    #[test]
    fn a_log_read_from_its_head_advances_from_that_head() {
        let head = 45_949_247;
        let (tracker, url) = tracker_with("https://fresh.example", head);

        for offset in 0..3 {
            tracker.record_ack(&url, head + offset);
        }
        assert_eq!(tracker.acked_index("https://fresh.example"), Some(head + 3));
    }

    /// The gap the live dedup and parse failures leave. A watcher does not
    /// publish every index it reads; if an unpublished index never settles,
    /// the position stops there and every later acknowledgement accumulates.
    #[test]
    fn an_index_that_is_never_published_does_not_pin_the_position() {
        let (tracker, url) = tracker_with("https://log.example", 100);

        tracker.record_ack(&url, 100);
        // 101 produced no record at all.
        tracker.record_skipped(&url, 101);
        for index in 102..1102 {
            tracker.record_ack(&url, index);
        }

        assert_eq!(
            tracker.acked_index("https://log.example"),
            Some(1102),
            "a settled skip must let the prefix close over it"
        );
        assert_eq!(
            tracker.pending(),
            0,
            "nothing should be left waiting behind the skip"
        );
    }

    /// Without the skip, this is exactly the failure: the position sticks and
    /// the later acknowledgements are retained indefinitely.
    #[test]
    fn an_unsettled_index_is_what_pins_the_position() {
        let (tracker, url) = tracker_with("https://log.example", 100);

        tracker.record_ack(&url, 100);
        for index in 102..1102 {
            tracker.record_ack(&url, index);
        }

        assert_eq!(tracker.acked_index("https://log.example"), Some(101));
        assert_eq!(tracker.pending(), 1000);
    }

    #[test]
    fn retry_backoff_grows_and_is_capped() {
        assert!(retry_delay(1) < retry_delay(4));
        assert_eq!(retry_delay(20), retry_delay(30), "must reach a ceiling");
        assert!(retry_delay(30) <= Duration::from_secs(30));
    }

    /// Logs must not share a position.
    #[test]
    fn positions_are_tracked_per_log() {
        let tracker = AckTracker::default();
        tracker.resume_at("https://a.example", 0);
        tracker.resume_at("https://b.example", 0);
        let a: Arc<str> = Arc::from("https://a.example");
        let b: Arc<str> = Arc::from("https://b.example");

        tracker.record_ack(&a, 0);
        tracker.record_ack(&a, 1);
        tracker.record_ack(&b, 0);

        assert_eq!(tracker.acked_index("https://a.example"), Some(2));
        assert_eq!(tracker.acked_index("https://b.example"), Some(1));
    }
}
