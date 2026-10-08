//! Reassemble VP8 RTP payloads into one access unit.
//!
//! webrtc-rs hands the app individual RTP packets. Android's MediaCodec
//! decoder needs a complete VP8 frame, so packets are concatenated until
//! the RTP marker bit. A new partition start drops an unfinished frame.
//! The buffer is capped so a missing marker cannot grow without limit.

use bytes::Bytes;
use rtp::codecs::vp8::Vp8Packet;
use rtp::packetizer::Depacketizer;

use crate::calling::media_policy::MAX_VIDEO_ACCESS_UNIT_BYTES;

#[derive(Default)]
pub struct Vp8Assembler {
    packet: Vp8Packet,
    frame: Vec<u8>,
    started: bool,
}

impl Vp8Assembler {
    /// Push one RTP payload. Returns a complete access unit when `marker`
    /// closes a frame that began with a partition head.
    pub fn push(&mut self, payload: &[u8], marker: bool) -> Option<Vec<u8>> {
        let part = match self.packet.depacketize(&Bytes::copy_from_slice(payload)) {
            Ok(part) => part,
            Err(_) => {
                self.frame.clear();
                self.started = false;
                return None;
            }
        };
        if self.packet.s == 1 {
            self.frame.clear();
            self.started = true;
        }
        if !self.started {
            return None;
        }
        if self.frame.len().saturating_add(part.len()) > MAX_VIDEO_ACCESS_UNIT_BYTES {
            self.frame.clear();
            self.started = false;
            return None;
        }
        self.frame.extend_from_slice(&part);
        if !marker {
            return None;
        }
        self.started = false;
        let frame = std::mem::take(&mut self.frame);
        if frame.is_empty() {
            None
        } else {
            Some(frame)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_packet_frame_is_emitted_on_marker() {
        let mut assembler = Vp8Assembler::default();
        // S=1, no extension. Four bytes is the depacketizer minimum.
        let payload = [0x10u8, 0x11, 0x22, 0x33];
        assert!(assembler.push(&payload, false).is_none());
        // A marker without a new start continues the same frame.
        let frame = assembler
            .push(&[0x00, 0x44, 0x55, 0x66], true)
            .expect("marker closes the frame");
        assert_eq!(frame, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn packet_before_partition_start_is_dropped() {
        let mut assembler = Vp8Assembler::default();
        assert!(assembler.push(&[0x00, 1, 2, 3], true).is_none());
    }
}
