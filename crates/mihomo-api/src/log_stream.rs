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
