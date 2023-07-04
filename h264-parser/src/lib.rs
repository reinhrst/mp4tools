use std::fmt;
use std::fs::File;
use std::io::{Read, };
use circular::Buffer;

use winnow::{
    binary::{bits},
    stream::{Partial, StreamIsPartial},
    combinator::{dispatch, eof, alt},
    token,
    IResult,
    Parser,
    Bytes,
    error,
    stream::Offset,
};

type Stream<'i> = Partial<&'i Bytes>;

fn stream(b: &[u8]) -> Stream<'_> {
    Stream::new(Bytes::new(b))
}
//
// enum NALUnitType {
//     SliceOfNonIDRPicture = 1,
//     // SliceOfDataPartitionA = 2,
//     // SliceOfDataPartitionB = 3,
//     // SliceOfDataPartitionC = 4,
//     SliceOfIDRPicture = 5,
//     SEI = 6,
//     SPS = 7,
//     PPS = 8,
//     AUD = 9,
//     EndOfSequence = 10,
//     EndOfStream = 11,
//     // FilterData = 12,
//     // SPSExt = 13,
//     // PrefixNALUnit = 14,
//     // SubsetSPS = 15,
//     // SliceLayerWithoutPartitioning = 19,
//     // CodedSliceExtension = 20,
// }

trait NALUnitWithType {
    const NU_TYPE: u8;
}


pub struct NonIDRPictureNU {
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}

impl NALUnitWithType for NonIDRPictureNU {
    const NU_TYPE: u8 = 1;
}

impl fmt::Debug for NonIDRPictureNU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NonIDRPicture: {} {:x?}", self.ref_idc, &self.rest[..(16.min(self.rest.len()))])
    }
}

pub struct IDRPictureNU {
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}

impl NALUnitWithType for IDRPictureNU {
    const NU_TYPE: u8 = 5;
}

impl fmt::Debug for IDRPictureNU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IDRPicture: {} {:x?}", self.ref_idc, &self.rest[..(16.min(self.rest.len()))])
    }
}

pub struct UnknownNU {
    pub nal_unit_type: u8,
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}


impl fmt::Debug for UnknownNU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UnknownNALUntit: {}, {} {:x?}", self.nal_unit_type, self.ref_idc, &self.rest[..(16.min(self.rest.len()))])
    }
}
// #[derive(Debug)]
// pub struct IDRNALUnit {
//     pub ref_idc: u8,
//     pub rest: Vec<u8>,
// }
//
// #[derive(Debug)]
// pub struct SEINALUnit {
//     pub ref_idc: u8,
//     pub rest: Vec<u8>,
// }
//
// #[derive(Debug)]
// pub struct SPSNALUnit {
//     pub ref_idc: u8,
//     pub rest: Vec<u8>,
// }
//
// #[derive(Debug)]
// pub struct PPSNALUnit {
//     pub ref_idc: u8,
//     pub rest: Vec<u8>,
// }
//
// #[derive(Debug)]
// pub struct AUDNALUnit {
//     pub ref_idc: u8,
//     pub rest: Vec<u8>,
// }
//

#[derive(Debug)]
pub enum NALUnit {
    NonIDRPicture(NonIDRPictureNU),
    IDRPicture(IDRPictureNU),
    Unknown(UnknownNU),
    // IDR(IDRNALUnit),
    // SEI(SEINALUnit),
    // SPS(SPSNALUnit),
    // PPS(PPSNALUnit),
    // AUD(AUDNALUnit),
    // EndOfSequence(),
    // EndOfStream(),
    // Unknown(u8, Vec<u8>),
}

/// We will read the file in chunks of this size
const CHUNK_SIZE: usize = 10 * 1024;
const NAL_BOUNDARY: &[u8] = b"\x00\x00\x00\x01";

// fn parse_nal_unit_non_idr(input: &[u8]) -> IResult<&[u8], NALUnit> {
//     let (input, nal_ref_idc) = take_nal_type(NALUnitType::SliceOfNonIDRPicture as u8)(input)?;
//     Ok((&[], NALUnit::NonIDR(NonIDRNALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
// }
//
// fn parse_nal_unit_idr(input: &[u8]) -> IResult<&[u8], NALUnit> {
//     let (input, nal_ref_idc) = take_nal_type(NALUnitType::SliceOfIDRPicture as u8)(input)?;
//     Ok((&[], NALUnit::IDR(IDRNALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
// }
//
// fn parse_nal_unit_sei(input: &[u8]) -> IResult<&[u8], NALUnit> {
//     let (input, nal_ref_idc) = take_nal_type(NALUnitType::SEI as u8)(input)?;
//     Ok((&[], NALUnit::SEI(SEINALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
// }
//
// fn parse_nal_unit_sps(input: &[u8]) -> IResult<&[u8], NALUnit> {
//     let (input, nal_ref_idc) = take_nal_type(NALUnitType::SPS as u8)(input)?;
//     Ok((&[], NALUnit::SPS(SPSNALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
// }
//
// fn parse_nal_unit_pps(input: &[u8]) -> IResult<&[u8], NALUnit> {
//     let (input, nal_ref_idc) = take_nal_type(NALUnitType::PPS as u8)(input)?;
//     Ok((&[], NALUnit::PPS(PPSNALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
// }
//
// fn parse_nal_unit_aud(input: &[u8]) -> IResult<&[u8], NALUnit> {
//     let (input, nal_ref_idc) = take_nal_type(NALUnitType::AUD as u8)(input)?;
//     Ok((&[], NALUnit::AUD(AUDNALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
// }
//
// fn parse_nal_unit_end_of_stream(input: &[u8]) -> IResult<&[u8], NALUnit> {
//     let (input, _) = bytes::complete::tag(&[NALUnitType::EndOfStream as u8][..])(input)?;
//     assert_eq!(input.len(), 0);
//     Ok((&[], NALUnit::EndOfStream()))
// }
//
// fn parse_nal_unit_end_of_sequence(input: &[u8]) -> IResult<&[u8], NALUnit> {
//     let (input, _) = bytes::complete::tag(&[NALUnitType::EndOfSequence as u8][..])(input)?;
//     assert_eq!(input.len(), 0);
//     Ok((&[], NALUnit::EndOfSequence()))
// }
//
// fn parse_nal_unit_unknown(input: &[u8]) -> IResult<&[u8], NALUnit> {
//     let (rest, nal_type) = bytes::complete::take(1usize)(input)?;
//     Ok((&[], NALUnit::Unknown(nal_type[0], rest.to_vec())))
// }
//

fn parse_till_nal_unit_end(input: Stream) -> IResult<Stream, &[u8]> {
    alt((token::take_until0(NAL_BOUNDARY), token::take_while(0.., |_| true))).parse_next(input)
}

fn parse_nal_unit_type_and_ref_idc(input: Stream) -> IResult<Stream, (u8, u8)> {
    let (input, (ref_idc, nal_unit_type)) = bits::bits::<_, _, error::Error<(_, usize)>, _, _>((bits::take(3_usize), bits::take(5_usize))).parse_next(input)?;
    return Ok((input, (nal_unit_type, ref_idc)))
}

fn parse_non_idr_picture_nal_unit(ref_idc: u8) -> impl FnMut(Stream) -> IResult<Stream, NALUnit> {
    move |input| {
        let (input, rest) = parse_till_nal_unit_end(input)?;
        Ok((input, NALUnit::NonIDRPicture(NonIDRPictureNU { ref_idc, rest: rest.to_vec()})))
    }
}

fn parse_idr_picture_nal_unit(ref_idc: u8) -> impl FnMut(Stream) -> IResult<Stream, NALUnit> {
    move |input| {
        let (input, rest) = parse_till_nal_unit_end(input)?;
        Ok((input, NALUnit::IDRPicture(IDRPictureNU { ref_idc, rest: rest.to_vec()})))
    }
}

fn parse_unknown_nal_unit(nal_unit_type: u8, ref_idc: u8) -> impl FnMut(Stream) -> IResult<Stream, NALUnit> {
    move |input| {
        let (input, rest) = parse_till_nal_unit_end(input)?;
        Ok((input, NALUnit::Unknown(UnknownNU { nal_unit_type, ref_idc, rest: rest.to_vec()})))
    }
}

fn parse_nal_unit(input: Stream) -> IResult<Stream, NALUnit> {
    let (input, _) = token::tag(NAL_BOUNDARY).parse_next(input)?;
    dispatch!(parse_nal_unit_type_and_ref_idc;
        (NonIDRPictureNU::NU_TYPE, ref_idc) => parse_non_idr_picture_nal_unit(ref_idc),
        (IDRPictureNU::NU_TYPE, ref_idc) => parse_idr_picture_nal_unit(ref_idc),
        (nu_type, ref_idc) => parse_unknown_nal_unit(nu_type, ref_idc),
    ).parse_next(input)
}

pub struct FileIterator {
    file: File
}

impl FileIterator {
    pub fn new(file: File) -> FileIterator {
        FileIterator { file }
    }
}

impl Iterator for FileIterator {
    type Item = Vec<u8>;
    
    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer: Vec<u8> = vec![0u8; CHUNK_SIZE];
        let len = self.file.read(&mut buffer).expect("Cannot read file");
        if len == 0 {
            // For now assuming EOF; probably in production code you might want to do something
            // else
            None
        } else {
            buffer.truncate(len);
            Some(buffer)
        }
    }
}

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
    type Item = NALUnit;

    fn next(&mut self) -> Option<Self::Item> {
        if self.has_reached_eof && self.buffer.available_data() == 0 {
            return None;
        }
        loop {
            //println!("{}, {}", self.has_reached_eof , self.buffer.available_data());
            let mut input = stream(self.buffer.data());
            if self.has_reached_eof {
                let _ = input.complete();
            }
            match parse_nal_unit(input) {
                Ok((remainer, return_value)) => {
                    let consumed = input.offset_to(&remainer);
                    self.buffer.consume(consumed);
                    return Some(return_value);
                }
                Err(error::ErrMode::Incomplete(_)) => {
                    //println!("More data needed (now {} bytes availble)", self.buffer.available_data());
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
