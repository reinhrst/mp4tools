pub mod packets;
pub mod crc;
pub mod psi_packet;
pub mod stream;
use circular::Buffer;
use std::{collections, io::Read};

use winnow::{error, stream::Offset};

const CHUNK_SIZE: usize = 10 * 1024;

pub struct MTSPacketIterator {
    input_reader: Box<dyn Read>,
    buffer: Buffer,
    has_reached_eof: bool,
}

impl MTSPacketIterator {
    pub fn new(input_reader: Box<dyn Read>) -> MTSPacketIterator {
        return Self {
            input_reader,
            buffer: Buffer::with_capacity(CHUNK_SIZE),
            has_reached_eof: false,
        };
    }
}

impl Iterator for MTSPacketIterator {
    type Item = packets::Packet;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.has_reached_eof && self.buffer.empty() {
                return None;
            }
            let input = stream::partialstream(self.buffer.data(), self.has_reached_eof);
            match packets::Packet::parse(input) {
                Ok((remainer, return_value)) => {
                    let consumed = input.offset_to(&remainer);
                    self.buffer.consume(consumed);
                    return Some(return_value);
                }
                Err(error::ErrMode::Incomplete(_)) => {
                    if self.buffer.position() + self.buffer.available_space() >= CHUNK_SIZE {
                        self.buffer.shift();
                    } else {
                        self.buffer.grow(self.buffer.capacity() + CHUNK_SIZE);
                    }
                    match self.input_reader.read(self.buffer.space()) {
                        Ok(read) => {
                            self.buffer.fill(read);
                            if read == 0 {
                                self.has_reached_eof = true;
                            }
                            continue;
                        }
                        Err(e) => panic!("error: {}", e),
                    }
                }
                Err(e) => panic!("Parse error: {}", e),
            };
        }
    }
}

#[derive(Debug)]
pub enum Element {
    PATTable(psi_packet::PATTable),
}

struct MapEntry {
    buffer: Buffer,
    complete_element_cutoff: Option<usize>,
}

impl MapEntry {
    fn new() -> Self {
        Self {
            buffer: Buffer::with_capacity(CHUNK_SIZE),
            complete_element_cutoff: None,
        }
    }
}

pub struct ElementIterator {
    packet_stream_map: collections::HashMap<u16, MapEntry>,
    packet_iterator: MTSPacketIterator,
    last_pid: Option<u16>,
}

impl ElementIterator {
    const PAT_PID: u16 = 0x0;
    const PADDING_PID: u16 = 0x1fff;
    pub fn new(packet_iterator: MTSPacketIterator) -> Self {
        Self {
            packet_stream_map: collections::HashMap::new(),
            packet_iterator,
            last_pid: None,
        }
    }
}

impl Iterator for ElementIterator {
    type Item = Element;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(last_pid) = self.last_pid {
            if let Some(element) = self.parse_pid_data_for_pid(&last_pid) {
                return Some(element);
            } else {
                self.last_pid = None;
            }
        }
        loop {
            match self.packet_iterator.next() {
                None => {
                    // no more data; parse the data items still waiting
                    let Some(pid) = self.packet_stream_map.keys().next() else {
                        return None;
                    };
                    let pid = &pid.clone();
                    // TODO: entry.complete_element_cutoff = Some(entry.buffer.available_data());
                    return self.parse_pid_data_for_pid(pid);
                }
                Some(packet) => {
                    if packet.pid == Self::PADDING_PID {
                        continue;
                    }
                    self.last_pid = Some(packet.pid);
                    if !self.packet_stream_map.contains_key(&packet.pid)
                    {
                        if packet.payload_unit_start_indicator {
                            self.packet_stream_map.insert(packet.pid, MapEntry::new());
                        } else {
                            // skipping since not start
                            continue;
                        }
                    }
                    let mut entry = self
                        .packet_stream_map
                        .get_mut(&packet.pid)
                        .expect("Pid should exist");
                    let Some(data) = packet.payload_data else {
                        continue;
                    };
                    if entry.buffer.available_space() < data.data.len() {
                        entry
                            .buffer
                            .grow(entry.buffer.capacity() + CHUNK_SIZE.max(data.data.len()));
                    }
                    assert!(entry.buffer.available_space() >= data.data.len());
                    let was_empty = entry.buffer.empty();
                    entry.buffer.space()[..data.data.len()].copy_from_slice(&data.data);
                    entry.buffer.fill(data.data.len());
                    if packet.payload_unit_start_indicator {
                        let complete_element_cutoff =
                            entry.buffer.available_data() - data.data.len() + data.cutoff as usize;

                        if was_empty {
                            // everything before the buffer is from previous item, skip
                            entry.buffer.consume(complete_element_cutoff);
                        } else {
                            entry.complete_element_cutoff = Some(complete_element_cutoff);
                        }
                    }
                    if let Some(element) = self.parse_pid_data_for_pid(&packet.pid) {
                        return Some(element);
                    }
                }
            }
        }
    }
}

impl ElementIterator {
    fn parse_pid_data_for_pid(&mut self, pid: &u16) -> Option<Element> {
        let Some(entry) = self.packet_stream_map.get_mut(pid) else {
            return None;
        };
        let input = match entry.complete_element_cutoff {
            Some(cutoff) => stream::partialstream(&entry.buffer.data()[..cutoff], true),
            None => stream::partialstream(entry.buffer.data(), false),
        };
        if *pid == Self::PAT_PID {
            return match psi_packet::PATTable::parse(input) {
                Ok((remainder, pat_table)) => {
                    let consumed = input.offset_to(&remainder);
                    entry.buffer.consume(consumed);
                    if entry.buffer.empty() {
                        self.packet_stream_map.remove(&pid);
                    } else {
                        entry.complete_element_cutoff = None;
                    }
                    Some(Element::PATTable(pat_table))
                }
                Err(error::ErrMode::Incomplete(_)) => None,
                Err(e) => panic!("Parse error: {}", e),
            };
        } else {
            None
        }
    }
}
