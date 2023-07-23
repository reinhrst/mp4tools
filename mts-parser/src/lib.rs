pub mod stream;
pub mod packets;
use std::io::Read;
use circular::Buffer;

use winnow::{
    error,
    stream::Offset,
};

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
        }
    }
}

impl Iterator for MTSPacketIterator {
    type Item = packets::Packet;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.has_reached_eof && self.buffer.available_data() == 0 {
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
                        },
                        Err(e) => panic!("error: {}", e),
                    }
                }
                Err(e) => panic!("Parse error: {}", e),
            };
        }
    }
}
