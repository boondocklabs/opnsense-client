use std::{mem, time::Duration};

use bytes::Bytes;
use serde::de::DeserializeOwned;

use crate::{Error, Result};

/// One SSE message. Comments and frames without a `data` field are not yielded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// The `event` field, or `message` when no type was specified.
    pub event: String,
    /// Data lines joined with newlines, without the final newline.
    pub data: String,
    /// Most recently received event ID (empty if none, or explicitly reset).
    pub id: String,
    /// Most recently received valid retry hint. Reconnection is caller-managed.
    pub retry: Option<Duration>,
}

impl Event {
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_str(&self.data)?)
    }
}

/// A pull-based, bounded SSE reader. Does not buffer the entire response.
/// Dropping it disconnects. EOF returns `None`; timeouts and transport/parser
/// errors terminate the stream. There are no automatic retries or reconnects.
pub struct EventStream {
    response: Option<reqwest::Response>,
    chunk: Bytes,
    offset: usize,
    parser: Parser,
    timeout: Duration,
    finished: bool,
}

impl EventStream {
    pub(crate) fn new(response: reqwest::Response, timeout: Duration, limit: usize) -> Self {
        Self {
            response: Some(response),
            chunk: Bytes::new(),
            offset: 0,
            parser: Parser::new(limit),
            timeout,
            finished: false,
        }
    }

    /// Wait for a complete event. Cancellation preserves partially parsed data.
    /// The deadline starts anew on each call and does not count time spent
    /// processing the previous event. SSE comments do not reset the deadline.
    pub async fn next_event(&mut self) -> Result<Option<Event>> {
        if self.finished {
            return Ok(None);
        }
        let result = tokio::time::timeout(self.timeout, self.read_event())
            .await
            .map_err(|_| Error::Timeout)
            .and_then(|result| result);
        if !matches!(result, Ok(Some(_))) {
            self.finished = true;
            self.response = None;
            self.chunk = Bytes::new();
        }
        result
    }

    /// Deserialize the next event's data. A JSON decode error consumes only
    /// that event, so subsequent calls can read later messages.
    pub async fn next_json<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        self.next_event()
            .await?
            .map(|event| event.json())
            .transpose()
    }

    async fn read_event(&mut self) -> Result<Option<Event>> {
        loop {
            while self.offset < self.chunk.len() {
                let byte = self.chunk[self.offset];
                self.offset += 1;
                if let Some(event) = self.parser.push(byte)? {
                    return Ok(Some(event));
                }
            }
            match self
                .response
                .as_mut()
                .expect("unfinished stream has a response")
                .chunk()
                .await?
            {
                Some(chunk) => {
                    self.chunk = chunk;
                    self.offset = 0;
                }
                // SSE dispatches only at a blank line, not at EOF.
                None => return Ok(None),
            }
        }
    }
}

struct Parser {
    line: Vec<u8>,
    data: String,
    event: String,
    id: String,
    retry: Option<Duration>,
    frame_bytes: usize,
    limit: usize,
    skip_lf: bool,
    first_line: bool,
}

impl Parser {
    fn new(limit: usize) -> Self {
        Self {
            line: Vec::new(),
            data: String::new(),
            event: String::new(),
            id: String::new(),
            retry: None,
            frame_bytes: 0,
            limit,
            skip_lf: false,
            first_line: true,
        }
    }

    fn push(&mut self, byte: u8) -> Result<Option<Event>> {
        if mem::take(&mut self.skip_lf) && byte == b'\n' {
            return Ok(None);
        }
        if self.frame_bytes == self.limit {
            return Err(Error::ResponseTooLarge);
        }
        self.frame_bytes += 1;
        if byte != b'\n' && byte != b'\r' {
            self.line.push(byte);
            return Ok(None);
        }
        self.skip_lf = byte == b'\r';
        let bytes = mem::take(&mut self.line);
        let bytes = if mem::take(&mut self.first_line) {
            bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes)
        } else {
            &bytes
        };
        let line = String::from_utf8_lossy(bytes);
        if line.is_empty() {
            self.frame_bytes = 0;
            let event = mem::take(&mut self.event);
            if self.data.is_empty() {
                return Ok(None);
            }
            self.data.pop(); // Remove the newline appended by the last data field.
            return Ok(Some(Event {
                event: if event.is_empty() {
                    "message".into()
                } else {
                    event
                },
                data: mem::take(&mut self.data),
                id: self.id.clone(),
                retry: self.retry,
            }));
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = line.split_once(':').unwrap_or((&line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => {
                self.data.push_str(value);
                self.data.push('\n');
            }
            "event" => self.event = value.into(),
            "id" if !value.contains('\0') => self.id = value.into(),
            "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                if let Ok(milliseconds) = value.parse::<u64>() {
                    self.retry = Some(Duration::from_millis(milliseconds));
                }
            }
            _ => {}
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> Vec<Event> {
        let mut parser = Parser::new(4096);
        bytes
            .iter()
            .filter_map(|b| parser.push(*b).unwrap())
            .collect()
    }

    #[test]
    fn parses_bom_mixed_newlines_unicode_multiline_and_metadata() {
        let events = parse("\u{feff}: heartbeat\r\nid: 42\revent: cpu\nretry: 1500\r\ndata: héllo\r\ndata: world\r\n\r\ndata:\n\n".as_bytes());
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            Event {
                event: "cpu".into(),
                data: "héllo\nworld".into(),
                id: "42".into(),
                retry: Some(Duration::from_millis(1500))
            }
        );
        assert_eq!(events[1].event, "message");
        assert_eq!(events[1].data, "");
        assert_eq!(events[1].id, "42");
    }

    #[test]
    fn ignores_comments_unknown_fields_bad_ids_and_retry_values() {
        let events = parse(b"id: kept\nretry: 123\n\nevent: discarded\n\n: hi\nunknown: x\nid: invalid\0id\nretry: -1\nretry: +2\nretry: 999999999999999999999999\ndata:  one space\n\nid\nretry: nope\ndata: end\n\ndata: unfinished");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "message");
        assert_eq!(events[0].id, "kept");
        assert_eq!(events[0].data, " one space");
        assert_eq!(events[0].retry, Some(Duration::from_millis(123)));
        assert_eq!(events[1].id, "");
    }

    #[test]
    fn bounds_unterminated_lines_and_combined_frame_fields() {
        for frame in [b"data: 123456789".as_slice(), b": x\n: x\n: x\n: x\n"] {
            let mut parser = Parser::new(10);
            assert!(
                frame
                    .iter()
                    .any(|b| matches!(parser.push(*b), Err(Error::ResponseTooLarge)))
            );
        }
        let mut parser = Parser::new(9);
        for byte in b"data: 1\n\ndata: 2\n\n" {
            parser.push(*byte).unwrap();
        }
    }
}
