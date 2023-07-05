pub mod nalunits;
pub mod stream;

use std::io::Read;
use circular::Buffer;

use winnow::{
    error,
    stream::Offset,
};

/// We will read the file in chunks of this size
const CHUNK_SIZE: usize = 10 * 1024;


pub struct NALUnitIterator {
    input_reader: Box<dyn Read>,
    buffer: Buffer,
    has_reached_eof: bool,
    
}


impl NALUnitIterator {
    pub fn new(input_reader: Box<dyn Read>) -> NALUnitIterator {
        return Self {
            input_reader,
            buffer: Buffer::with_capacity(CHUNK_SIZE),
            has_reached_eof: false,
        }
    }
}

impl Iterator for NALUnitIterator {
    type Item = nalunits::NALUnit;

    fn next(&mut self) -> Option<Self::Item> {
        if self.has_reached_eof && self.buffer.available_data() == 0 {
            return None;
        }
        loop {
            //println!("{}, {}", self.has_reached_eof , self.buffer.available_data());
            let mut input = stream::partialstream(self.buffer.data(), self.has_reached_eof);
            match nalunits::parse_nal_unit(input) {
                Ok((remainer, return_value)) => {
                    let consumed = input.offset_to(&remainer);
                    self.buffer.consume(consumed);
                    return Some(return_value);
                }
                Err(error::ErrMode::Incomplete(_)) => {
                    // println!("More data needed (now {} bytes availble)", self.buffer.available_data());
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
