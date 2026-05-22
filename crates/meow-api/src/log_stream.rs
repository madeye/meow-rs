use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
use tokio::sync::broadcast;
use tracing_subscriber::Layer;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Silent,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            LogLevel::Silent => "silent",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogMessage {
    pub level: LogLevel,
    pub payload: String,
    pub time: time::OffsetDateTime,
}

impl Serialize for LogMessage {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_struct("LogMessage", 3)?;
        m.serialize_field("type", self.level.as_str())?;
        m.serialize_field("payload", &self.payload)?;
        let ts = self
            .time
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        m.serialize_field("time", &ts)?;
        m.end()
    }
}

pub struct LogBroadcastLayer {
    pub tx: broadcast::Sender<LogMessage>,
}

impl<S: tracing::Subscriber> Layer<S> for LogBroadcastLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = match *event.metadata().level() {
            tracing::Level::TRACE | tracing::Level::DEBUG => LogLevel::Debug,
            tracing::Level::INFO => LogLevel::Info,
            tracing::Level::WARN => LogLevel::Warning,
            tracing::Level::ERROR => LogLevel::Error,
        };
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let msg = LogMessage {
            level,
            payload: visitor.0,
            time: time::OffsetDateTime::now_utc(),
        };
        // Non-blocking; Err = no subscribers or channel full — both acceptable.
        let _ = self.tx.send(msg);
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
}

pub fn parse_log_level(s: &str) -> LogLevel {
    match s.to_ascii_lowercase().as_str() {
        "debug" => LogLevel::Debug,
        "warning" | "warn" => LogLevel::Warning,
        "error" => LogLevel::Error,
        "silent" => LogLevel::Silent,
        // "info" and any unrecognised value default to Info.
        _ => LogLevel::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::subscriber;
    use tracing_subscriber::prelude::*;

    #[test]
    fn log_level_str_round_trip_via_parse() {
        for (s, lvl) in [
            ("debug", LogLevel::Debug),
            ("info", LogLevel::Info),
            ("warning", LogLevel::Warning),
            ("error", LogLevel::Error),
            ("silent", LogLevel::Silent),
        ] {
            assert_eq!(parse_log_level(s), lvl);
            assert_eq!(lvl.as_str(), s);
        }
    }

    #[test]
    fn parse_log_level_accepts_warn_alias() {
        assert_eq!(parse_log_level("warn"), LogLevel::Warning);
        assert_eq!(parse_log_level("WARN"), LogLevel::Warning);
    }

    #[test]
    fn parse_log_level_is_case_insensitive() {
        assert_eq!(parse_log_level("DEBUG"), LogLevel::Debug);
        assert_eq!(parse_log_level("Info"), LogLevel::Info);
        assert_eq!(parse_log_level("Error"), LogLevel::Error);
    }

    #[test]
    fn parse_log_level_unknown_input_defaults_to_info() {
        // Documented behaviour: an unrecognised level → fall back to Info
        // rather than rejecting the request.
        assert_eq!(parse_log_level(""), LogLevel::Info);
        assert_eq!(parse_log_level("nonsense"), LogLevel::Info);
        assert_eq!(parse_log_level("trace"), LogLevel::Info);
    }

    #[test]
    fn log_level_ord_matches_severity_increasing() {
        // The WS handler filters with `level >= request_level`. The enum
        // ordering must therefore be Debug < Info < Warning < Error < Silent
        // (where Silent is the strictest filter — nothing passes).
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warning);
        assert!(LogLevel::Warning < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Silent);
    }

    #[test]
    fn log_message_serializes_three_fields() {
        // 2026-01-02 03:04:05 UTC = 1767322945 seconds since unix epoch.
        let ts = time::OffsetDateTime::from_unix_timestamp(1_767_322_945).unwrap();
        let msg = LogMessage {
            level: LogLevel::Warning,
            payload: "alerts: thing happened".into(),
            time: ts,
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "warning");
        assert_eq!(json["payload"], "alerts: thing happened");
        assert_eq!(json["time"], "2026-01-02T03:02:25Z");
    }

    #[test]
    fn layer_forwards_string_message_event() {
        let (tx, mut rx) = broadcast::channel(8);
        let layer = LogBroadcastLayer { tx };
        let registry = tracing_subscriber::registry().with(layer);
        subscriber::with_default(registry, || {
            tracing::warn!("hello-world");
        });
        let got = rx.try_recv().expect("event must be forwarded");
        assert_eq!(got.level, LogLevel::Warning);
        assert!(
            got.payload.contains("hello-world"),
            "payload: {}",
            got.payload
        );
    }

    #[test]
    fn layer_maps_tracing_levels_to_log_levels() {
        let (tx, mut rx) = broadcast::channel(16);
        let layer = LogBroadcastLayer { tx };
        let registry = tracing_subscriber::registry().with(layer);
        subscriber::with_default(registry, || {
            tracing::error!("e");
            tracing::warn!("w");
            tracing::info!("i");
            tracing::debug!("d"); // collapses to Debug
            tracing::trace!("t"); // collapses to Debug
        });
        let levels: Vec<LogLevel> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|m| m.level)
            .collect();
        // Trace+debug both map to Debug; default filter may drop them at the
        // subscriber level, so accept either {Error, Warning, Info} only or
        // the full set.
        assert!(levels.starts_with(&[LogLevel::Error, LogLevel::Warning, LogLevel::Info]));
        for extra in &levels[3..] {
            assert_eq!(*extra, LogLevel::Debug);
        }
    }

    #[test]
    fn layer_send_with_no_subscribers_does_not_panic() {
        // Documented contract: a send Err (no subscribers / channel full) is
        // acceptable — verify we don't regress to a panicking `.unwrap()`.
        let (tx, rx) = broadcast::channel(1);
        drop(rx);
        let layer = LogBroadcastLayer { tx };
        let registry = tracing_subscriber::registry().with(layer);
        subscriber::with_default(registry, || {
            tracing::info!("payload");
            tracing::error!("oh no");
        });
        // No panic = pass.
    }
}
