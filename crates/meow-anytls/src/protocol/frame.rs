use bytes::Bytes;

/// Frame header size: 1 (cmd) + 4 (stream_id) + 2 (data_len) = 7 bytes
pub const HEADER_OVERHEAD_SIZE: usize = 7;

/// Command types for AnyTLS protocol frames
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Padding data (waste bytes for traffic obfuscation)
    Waste = 0,
    /// Open a new stream
    Syn = 1,
    /// Push data through the stream
    Push = 2,
    /// Close the stream (EOF mark)
    Fin = 3,
    /// Client settings sent to server
    Settings = 4,
    /// Alert message
    Alert = 5,
    /// Update padding scheme
    UpdatePaddingScheme = 6,
    /// Server acknowledges stream open (since protocol version 2)
    SynAck = 7,
    /// Keep-alive request
    HeartRequest = 8,
    /// Keep-alive response
    HeartResponse = 9,
    /// Server settings sent to client (since protocol version 2)
    ServerSettings = 10,
}

impl From<u8> for Command {
    fn from(value: u8) -> Self {
        match value {
            0 => Command::Waste,
            1 => Command::Syn,
            2 => Command::Push,
            3 => Command::Fin,
            4 => Command::Settings,
            5 => Command::Alert,
            6 => Command::UpdatePaddingScheme,
            7 => Command::SynAck,
            8 => Command::HeartRequest,
            9 => Command::HeartResponse,
            10 => Command::ServerSettings,
            _ => Command::Waste, // Unknown command, treat as waste
        }
    }
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> Self {
        cmd as u8
    }
}

/// Frame defines a packet from or to be multiplexed into a single connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Command type
    pub cmd: Command,
    /// Stream identifier (0 for control frames)
    pub stream_id: u32,
    /// Frame payload data
    pub data: Bytes,
}

impl Frame {
    /// Create a new frame
    pub fn new(cmd: Command, stream_id: u32) -> Self {
        Self {
            cmd,
            stream_id,
            data: Bytes::new(),
        }
    }

    /// Create a new frame with data
    pub fn with_data(cmd: Command, stream_id: u32, data: Bytes) -> Self {
        Self {
            cmd,
            stream_id,
            data,
        }
    }

    /// Create a control frame (no data)
    pub fn control(cmd: Command, stream_id: u32) -> Self {
        Self::new(cmd, stream_id)
    }

    /// Create a data frame
    pub fn data(stream_id: u32, data: Bytes) -> Self {
        Self::with_data(Command::Push, stream_id, data)
    }

    /// Get the total frame size (header + data)
    pub fn total_size(&self) -> usize {
        HEADER_OVERHEAD_SIZE + self.data.len()
    }

    /// Check if this is a control frame (no data)
    pub fn is_control(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_conversion() {
        assert_eq!(Command::from(0), Command::Waste);
        assert_eq!(Command::from(1), Command::Syn);
        assert_eq!(u8::from(Command::Syn), 1);
    }

    #[test]
    fn test_frame_creation() {
        let frame = Frame::control(Command::Syn, 123);
        assert_eq!(frame.cmd, Command::Syn);
        assert_eq!(frame.stream_id, 123);
        assert!(frame.data.is_empty());
        assert_eq!(frame.total_size(), HEADER_OVERHEAD_SIZE);
    }

    #[test]
    fn test_frame_with_data() {
        let data = Bytes::from("hello");
        let frame = Frame::data(456, data.clone());
        assert_eq!(frame.cmd, Command::Push);
        assert_eq!(frame.stream_id, 456);
        assert_eq!(frame.data, data);
        assert_eq!(frame.total_size(), HEADER_OVERHEAD_SIZE + 5);
    }
}
