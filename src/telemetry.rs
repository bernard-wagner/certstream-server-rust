//! Bounded-label diagnostics. Timers record elapsed time even when a future
//! is cancelled; in-flight gauges are balanced by Drop. No URLs, indexes,
//! certificate hashes or error strings are used as metric labels.

use std::sync::Arc;
use std::time::Duration;

use metrics::{Gauge, Histogram, Label};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use reqwest::{RequestBuilder, Response};
use tokio::time::Instant;

const TIME_BUCKETS: &[f64] = &[
    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.3, 0.5, 1.0, 3.0, 10.0, 30.0, 60.0,
];

pub fn prometheus_builder() -> PrometheusBuilder {
    PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Prefix("certstream_ct_".into()), TIME_BUCKETS)
        .expect("valid CT timing buckets")
        .set_buckets_for_metric(Matcher::Prefix("certstream_nats_".into()), TIME_BUCKETS)
        .expect("valid NATS timing buckets")
}

pub fn describe_metrics() {
    metrics::describe_histogram!(
        "certstream_ct_http_seconds",
        metrics::Unit::Seconds,
        "HTTP headers/body elapsed time, excluding local pacing; includes cancelled phases"
    );
    metrics::describe_histogram!(
        "certstream_ct_stage_seconds",
        metrics::Unit::Seconds,
        "Elapsed work or local limiter/queue wait per watcher stage; stages can overlap across tasks"
    );
    metrics::describe_histogram!(
        "certstream_ct_wait_seconds",
        metrics::Unit::Seconds,
        "Actual watcher sleep time by reason, including interrupted sleeps"
    );
    metrics::describe_counter!(
        "certstream_ct_http_requests_total",
        "Requests receiving headers or failing before headers; cancelled requests excluded"
    );
    metrics::describe_counter!(
        "certstream_ct_response_body_bytes_total",
        metrics::Unit::Bytes,
        "Completed decoded byte/text bodies, not wire bytes; get-sth JSON excluded"
    );
    metrics::describe_counter!(
        "certstream_ct_entries_returned_total",
        "Entries decoded from responses, including replayed prefixes; abandoned prefetches excluded"
    );
    metrics::describe_counter!(
        "certstream_ct_entries_processed_total",
        "Entries advanced by processing, before durable ACK and independent of live dedup"
    );
    metrics::describe_gauge!(
        "certstream_ct_head_entries",
        "Most recently observed tree size, not a timestamp"
    );
    metrics::describe_gauge!(
        "certstream_ct_read_position",
        "Processed next-entry index, not the durable acknowledged position"
    );
    metrics::describe_gauge!(
        "certstream_nats_queue_depth",
        "Publisher queue usage sampled every 250ms; can include a reserved slot"
    );
    metrics::describe_gauge!(
        "certstream_nats_queue_capacity",
        "Configured publisher queue capacity"
    );
    metrics::describe_histogram!(
        "certstream_nats_enqueue_seconds",
        metrics::Unit::Seconds,
        "Time obtaining space in the publisher queue, including cancellations"
    );
    metrics::describe_histogram!(
        "certstream_nats_queue_residence_seconds",
        metrics::Unit::Seconds,
        "Time from enqueue to dequeue, excluding enqueue wait"
    );
    metrics::describe_histogram!(
        "certstream_nats_publish_seconds",
        metrics::Unit::Seconds,
        "Complete publish attempt including send and durable ACK, excluding retry backoff"
    );
    metrics::describe_histogram!(
        "certstream_nats_send_seconds",
        metrics::Unit::Seconds,
        "Time submitting a publish to the NATS client"
    );
    metrics::describe_histogram!(
        "certstream_nats_ack_seconds",
        metrics::Unit::Seconds,
        "Time awaiting JetStream's durable publish ACK"
    );
    metrics::describe_histogram!(
        "certstream_nats_retry_wait_seconds",
        metrics::Unit::Seconds,
        "Actual publisher retry sleep, including interruption"
    );
}

#[derive(Clone)]
pub(crate) struct Timing {
    duration: Histogram,
    active: Gauge,
}

impl Timing {
    pub(crate) fn new(name: &'static str, active: &'static str, labels: &[Label]) -> Self {
        let active = metrics::gauge!(active, labels.to_vec());
        // Do not reset an already registered gauge when another handle is made.
        active.increment(0.0);
        Self {
            duration: metrics::histogram!(name, labels.to_vec()),
            active,
        }
    }

    pub(crate) fn start(&self) -> Timer {
        self.active.increment(1.0);
        Timer {
            started: Instant::now(),
            timing: self.clone(),
        }
    }
}

pub(crate) struct Timer {
    started: Instant,
    timing: Timing,
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.timing
            .duration
            .record(self.started.elapsed().as_secs_f64());
        self.timing.active.decrement(1.0);
    }
}

#[derive(Clone)]
pub(crate) struct WatcherMetrics {
    labels: Arc<Vec<Label>>,
    processed: metrics::Counter,
    head: Gauge,
    position: Gauge,
}

impl WatcherMetrics {
    pub(crate) fn new(operator: &str, log: &str, source_id: &str, log_type: &'static str) -> Self {
        let labels = Arc::new(vec![
            Label::new("operator", crate::ct::normalize_operator(operator)),
            Label::new("log", log.to_owned()),
            Label::new("source_id", source_id.to_owned()),
            Label::new("log_type", log_type),
        ]);
        let processed = metrics::counter!(
            "certstream_ct_entries_processed_total",
            labels.as_ref().clone()
        );
        processed.increment(0);
        Self {
            processed,
            head: metrics::gauge!("certstream_ct_head_entries", labels.as_ref().clone()),
            position: metrics::gauge!("certstream_ct_read_position", labels.as_ref().clone()),
            labels,
        }
    }

    pub(crate) fn http(&self, endpoint: &'static str) -> HttpMetrics {
        let mut labels = self.labels.as_ref().clone();
        labels.push(Label::new("endpoint", endpoint));
        HttpMetrics::new(labels)
    }

    pub(crate) fn stage(&self, stage: &'static str) -> Timer {
        let mut labels = self.labels.as_ref().clone();
        labels.push(Label::new("stage", stage));
        Timing::new(
            "certstream_ct_stage_seconds",
            "certstream_ct_stage_active",
            &labels,
        )
        .start()
    }

    pub(crate) async fn sleep(&self, reason: &'static str, duration: Duration) {
        let mut labels = self.labels.as_ref().clone();
        labels.push(Label::new("reason", reason));
        let _timer = Timing::new(
            "certstream_ct_wait_seconds",
            "certstream_ct_wait_active",
            &labels,
        )
        .start();
        tokio::time::sleep(duration).await;
    }

    pub(crate) fn head(&self, head: u64) {
        self.head.set(head as f64);
    }

    pub(crate) fn position(&self, position: u64) {
        self.position.set(position as f64);
    }

    /// Entries whose position was advanced, including unparseable entries,
    /// excluding a replayed prefix and independent of live certificate dedup.
    pub(crate) fn processed(&self, count: u64) {
        self.processed.increment(count);
    }
}

#[derive(Clone)]
pub(crate) struct HttpMetrics {
    labels: Arc<Vec<Label>>,
    headers: Timing,
    body: Timing,
    bytes: metrics::Counter,
    entries: metrics::Counter,
}

impl HttpMetrics {
    fn new(labels: Vec<Label>) -> Self {
        let phase = |phase| {
            let mut labels = labels.clone();
            labels.push(Label::new("phase", phase));
            Timing::new(
                "certstream_ct_http_seconds",
                "certstream_ct_http_active",
                &labels,
            )
        };
        let bytes = metrics::counter!("certstream_ct_response_body_bytes_total", labels.clone());
        let entries = metrics::counter!("certstream_ct_entries_returned_total", labels.clone());
        bytes.increment(0);
        entries.increment(0);
        Self {
            headers: phase("headers"),
            body: phase("body"),
            bytes,
            entries,
            labels: Arc::new(labels),
        }
    }

    pub(crate) async fn send(
        &self,
        request: RequestBuilder,
    ) -> Result<MeasuredResponse, reqwest::Error> {
        let _timer = self.headers.start();
        let result = request.send().await;
        let status = match &result {
            Ok(response) => response.status().as_u16().to_string(),
            Err(error) if error.is_timeout() => "timeout".to_owned(),
            Err(_) => "transport_error".to_owned(),
        };
        let mut labels = self.labels.as_ref().clone();
        labels.push(Label::new("status", status));
        metrics::counter!("certstream_ct_http_requests_total", labels).increment(1);
        result.map(|response| MeasuredResponse {
            response,
            metrics: self.clone(),
        })
    }

    pub(crate) fn returned(&self, count: u64) {
        self.entries.increment(count);
    }

    pub(crate) async fn fetch(
        &self,
        request: RequestBuilder,
        description: &str,
    ) -> crate::ct::FetchOutcome {
        match self.send(request).await {
            Ok(response) if response.status().is_success() => match response.bytes().await {
                Ok(body) => crate::ct::FetchOutcome::Body(body),
                Err(error) => crate::ct::FetchOutcome::Net(error.to_string()),
            },
            Ok(response) => {
                let status = response.status();
                let retry_after = (status.as_u16() == 429)
                    .then(|| crate::ct::parse_retry_after(response.headers(), description));
                crate::ct::FetchOutcome::Http(status, retry_after)
            }
            Err(error) => crate::ct::FetchOutcome::Net(error.to_string()),
        }
    }

    fn body_result<T>(&self, result: &Result<T, reqwest::Error>) {
        if let Err(error) = result {
            let mut labels = self.labels.as_ref().clone();
            labels.push(Label::new(
                "reason",
                if error.is_timeout() {
                    "timeout"
                } else if error.is_decode() {
                    "decode"
                } else {
                    "transport_error"
                },
            ));
            metrics::counter!("certstream_ct_http_body_errors_total", labels).increment(1);
        }
    }
}

pub(crate) struct MeasuredResponse {
    response: Response,
    metrics: HttpMetrics,
}

impl MeasuredResponse {
    pub(crate) fn status(&self) -> reqwest::StatusCode {
        self.response.status()
    }
    pub(crate) fn headers(&self) -> &reqwest::header::HeaderMap {
        self.response.headers()
    }

    pub(crate) async fn bytes(self) -> Result<bytes::Bytes, reqwest::Error> {
        let _timer = self.metrics.body.start();
        let result = self.response.bytes().await;
        self.metrics.body_result(&result);
        if let Ok(body) = &result {
            self.metrics.bytes.increment(body.len() as u64);
        }
        result
    }

    pub(crate) async fn text(self) -> Result<String, reqwest::Error> {
        let _timer = self.metrics.body.start();
        let result = self.response.text().await;
        self.metrics.body_result(&result);
        if let Ok(text) = &result {
            self.metrics.bytes.increment(text.len() as u64);
        }
        result
    }

    // Preserve reqwest's JSON error and decoding behaviour. JSON responses
    // are timed but excluded from byte accounting (only tiny get-sth heads).
    pub(crate) async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, reqwest::Error> {
        let _timer = self.metrics.body.start();
        let result = self.response.json().await;
        self.metrics.body_result(&result);
        result
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use metrics_exporter_prometheus::PrometheusHandle;

    pub(crate) fn recorded(test: impl FnOnce(&PrometheusHandle)) -> String {
        let recorder = prometheus_builder().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            describe_metrics();
            test(&handle);
        });
        handle.render()
    }

    pub(crate) fn value(snapshot: &str, name: &str, labels: &[(&str, &str)]) -> f64 {
        let line = snapshot
            .lines()
            .find(|line| {
                (line.starts_with(&format!("{name}{{")) || line.starts_with(&format!("{name} ")))
                    && labels
                        .iter()
                        .all(|(key, value)| line.contains(&format!("{key}=\"{value}\"")))
            })
            .unwrap_or_else(|| panic!("missing metric {name} {labels:?} in {snapshot}"));
        line.split_whitespace().last().unwrap().parse().unwrap()
    }

    pub(crate) fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn watcher() -> WatcherMetrics {
        WatcherMetrics::new("Google, Inc.", "test-log", "ctlog:test", "rfc6962")
    }

    #[test]
    fn timers_balance_overlapping_and_cancelled_work() {
        let snapshot = recorded(|handle| {
            let watcher = watcher();
            let first = watcher.stage("process");
            let second = watcher.stage("process");
            assert_eq!(
                value(
                    &handle.render(),
                    "certstream_ct_stage_active",
                    &[("stage", "process")]
                ),
                2.0
            );
            drop(first);
            drop(second);
            runtime().block_on(async {
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(20),
                        watcher.sleep("backoff", Duration::from_secs(30))
                    )
                    .await
                    .is_err()
                );
            });
        });
        assert_eq!(
            value(
                &snapshot,
                "certstream_ct_stage_active",
                &[("stage", "process")]
            ),
            0.0
        );
        assert_eq!(
            value(
                &snapshot,
                "certstream_ct_stage_seconds_count",
                &[("stage", "process")]
            ),
            2.0
        );
        assert_eq!(
            value(
                &snapshot,
                "certstream_ct_wait_active",
                &[("reason", "backoff")]
            ),
            0.0
        );
        assert_eq!(
            value(
                &snapshot,
                "certstream_ct_wait_seconds_count",
                &[("reason", "backoff")]
            ),
            1.0
        );
        assert!(
            value(
                &snapshot,
                "certstream_ct_wait_seconds_sum",
                &[("reason", "backoff")]
            ) >= 0.01
        );
        assert!(snapshot.contains("certstream_ct_wait_seconds_bucket{"));
        assert!(snapshot.contains("operator=\"google inc\""));
    }

    // A loopback HTTP server only: these tests never poll a real CT log.
    async fn serve(response: &'static [u8], delay: Duration) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let split = response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            stream.write_all(&response[..split]).await.unwrap();
            tokio::time::sleep(delay).await;
            let _ = stream.write_all(&response[split..]).await;
        });
        format!("http://{address}/")
    }

    #[test]
    fn http_separates_headers_body_and_decoded_bytes() {
        let snapshot = recorded(|_| {
            runtime().block_on(async {
                let watcher = watcher();
                let http = watcher.http("get_entries");
                let url = serve(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    Duration::from_millis(40),
                )
                .await;
                let client = reqwest::Client::builder().no_proxy().build().unwrap();
                let body = http
                    .send(client.get(url))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                assert_eq!(body.as_ref(), b"hello");
                http.returned(3);
                watcher.processed(2);
                watcher.head(100);
                watcher.position(99);
            })
        });
        assert_eq!(
            value(
                &snapshot,
                "certstream_ct_http_requests_total",
                &[("status", "200")]
            ),
            1.0
        );
        assert_eq!(
            value(&snapshot, "certstream_ct_response_body_bytes_total", &[]),
            5.0
        );
        assert_eq!(
            value(&snapshot, "certstream_ct_entries_returned_total", &[]),
            3.0
        );
        assert_eq!(
            value(&snapshot, "certstream_ct_entries_processed_total", &[]),
            2.0
        );
        assert_eq!(value(&snapshot, "certstream_ct_head_entries", &[]), 100.0);
        assert_eq!(value(&snapshot, "certstream_ct_read_position", &[]), 99.0);
        assert!(
            value(
                &snapshot,
                "certstream_ct_http_seconds_sum",
                &[("phase", "body")]
            ) >= 0.02
        );
        for phase in ["headers", "body"] {
            assert_eq!(
                value(&snapshot, "certstream_ct_http_active", &[("phase", phase)]),
                0.0
            );
            assert_eq!(
                value(
                    &snapshot,
                    "certstream_ct_http_seconds_count",
                    &[("phase", phase)]
                ),
                1.0
            );
        }
    }

    #[test]
    fn http_preserves_429_and_retry_after() {
        let snapshot = recorded(|_| {
            runtime().block_on(async {
            let http = watcher().http("tile_partial");
            let url = serve(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", Duration::ZERO).await;
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            assert!(matches!(http.fetch(client.get(url), "test").await, crate::ct::FetchOutcome::Http(reqwest::StatusCode::TOO_MANY_REQUESTS, Some(2000))));
        })
        });
        assert_eq!(
            value(
                &snapshot,
                "certstream_ct_http_requests_total",
                &[("status", "429")]
            ),
            1.0
        );
        assert_eq!(
            value(&snapshot, "certstream_ct_response_body_bytes_total", &[]),
            0.0
        );
    }

    #[test]
    fn http_counts_failed_body_without_claiming_bytes() {
        let snapshot = recorded(|_| {
            runtime().block_on(async {
                let http = watcher().http("tile_full");
                let url = serve(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort",
                    Duration::ZERO,
                )
                .await;
                let client = reqwest::Client::builder().no_proxy().build().unwrap();
                assert!(matches!(
                    http.fetch(client.get(url), "test").await,
                    crate::ct::FetchOutcome::Net(_)
                ));
            })
        });
        assert_eq!(
            value(&snapshot, "certstream_ct_http_body_errors_total", &[]),
            1.0
        );
        assert_eq!(
            value(&snapshot, "certstream_ct_http_active", &[("phase", "body")]),
            0.0
        );
        assert_eq!(
            value(&snapshot, "certstream_ct_response_body_bytes_total", &[]),
            0.0
        );
    }

    #[test]
    fn cancelled_http_body_releases_active_gauge() {
        let snapshot = recorded(|_| {
            runtime().block_on(async {
                let http = watcher().http("get_entries");
                let url = serve(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    Duration::from_secs(30),
                )
                .await;
                let client = reqwest::Client::builder().no_proxy().build().unwrap();
                let response = http.send(client.get(url)).await.unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), response.bytes())
                        .await
                        .is_err()
                );
            })
        });
        assert_eq!(
            value(&snapshot, "certstream_ct_http_active", &[("phase", "body")]),
            0.0
        );
        assert_eq!(
            value(
                &snapshot,
                "certstream_ct_http_seconds_count",
                &[("phase", "body")]
            ),
            1.0
        );
        assert_eq!(
            value(&snapshot, "certstream_ct_response_body_bytes_total", &[]),
            0.0
        );
    }
}
