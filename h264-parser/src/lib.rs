use std::cmp;
use std::error::Error;
use std::fs::File;
use std::io::Read;

use nom::{
    branch,
    bits,
    bytes,
    sequence,
    Err,
    IResult,
};

enum NALUnitType {
    SliceOfNonIDRPicture = 1,
    // SliceOfDataPartitionA = 2,
    // SliceOfDataPartitionB = 3,
    // SliceOfDataPartitionC = 4,
    SliceOfIDRPicture = 5,
    SEI = 6,
    SPS = 7,
    PPS = 8,
    AUD = 9,
    EndOfSequence = 10,
    EndOfStream = 11,
    // FilterData = 12,
    // SPSExt = 13,
    // PrefixNALUnit = 14,
    // SubsetSPS = 15,
    // SliceLayerWithoutPartitioning = 19,
    // CodedSliceExtension = 20,
}

#[derive(Debug)]
pub struct NonIDRNALUnit {
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}

#[derive(Debug)]
pub struct IDRNALUnit {
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}

#[derive(Debug)]
pub struct SEINALUnit {
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}

#[derive(Debug)]
pub struct SPSNALUnit {
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}

#[derive(Debug)]
pub struct PPSNALUnit {
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}

#[derive(Debug)]
pub struct AUDNALUnit {
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}


#[derive(Debug)]
pub enum NALUnit {
    NonIDR(NonIDRNALUnit),
    IDR(IDRNALUnit),
    SEI(SEINALUnit),
    SPS(SPSNALUnit),
    PPS(PPSNALUnit),
    AUD(AUDNALUnit),
    EndOfSequence(),
    EndOfStream(),
    Unknown(u8, Vec<u8>),
}

/// We will read the file in chunks of this size
const CHUNK_SIZE: usize = 10 * 1024 * 1024;
const NAL_BOUNDARY: &[u8] = b"\x00\x00\x01";
const NAL_BOUNDARY_WITH_PREFIX: &[u8] = b"\x00\x00\x00\x01";
const NAL_BOUNDARY_OPTIONAL_PREFIX: &u8 = &0u8;

fn take_nal_type(nal_type: u8) -> Box<dyn Fn(&[u8]) -> IResult<&[u8], u8>> {
    Box::new(move |input| {
        let result: IResult<&[u8], (u8, u8)> = bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
            sequence::tuple((
                bits::complete::take(3usize),
                bits::complete::tag(nal_type as u8, 5usize))))(input);
        match result {
            Ok((input, output)) => Ok((input, output.0)),
            Err(other) => Err(other),
        }
    })
}

fn parse_nal_unit_non_idr(input: &[u8]) -> IResult<&[u8], NALUnit> {
    let (input, nal_ref_idc) = take_nal_type(NALUnitType::SliceOfNonIDRPicture as u8)(input)?;
    Ok((&[], NALUnit::NonIDR(NonIDRNALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
}

fn parse_nal_unit_idr(input: &[u8]) -> IResult<&[u8], NALUnit> {
    let (input, nal_ref_idc) = take_nal_type(NALUnitType::SliceOfIDRPicture as u8)(input)?;
    Ok((&[], NALUnit::IDR(IDRNALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
}

fn parse_nal_unit_sei(input: &[u8]) -> IResult<&[u8], NALUnit> {
    let (input, nal_ref_idc) = take_nal_type(NALUnitType::SEI as u8)(input)?;
    Ok((&[], NALUnit::SEI(SEINALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
}

fn parse_nal_unit_sps(input: &[u8]) -> IResult<&[u8], NALUnit> {
    let (input, nal_ref_idc) = take_nal_type(NALUnitType::SPS as u8)(input)?;
    Ok((&[], NALUnit::SPS(SPSNALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
}

fn parse_nal_unit_pps(input: &[u8]) -> IResult<&[u8], NALUnit> {
    let (input, nal_ref_idc) = take_nal_type(NALUnitType::PPS as u8)(input)?;
    Ok((&[], NALUnit::PPS(PPSNALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
}

fn parse_nal_unit_aud(input: &[u8]) -> IResult<&[u8], NALUnit> {
    let (input, nal_ref_idc) = take_nal_type(NALUnitType::AUD as u8)(input)?;
    Ok((&[], NALUnit::AUD(AUDNALUnit {ref_idc: nal_ref_idc, rest: input[..cmp::min(input.len(), 20)].to_vec() } )))
}

fn parse_nal_unit_end_of_stream(input: &[u8]) -> IResult<&[u8], NALUnit> {
    let (input, _) = bytes::complete::tag(&[NALUnitType::EndOfStream as u8][..])(input)?;
    assert_eq!(input.len(), 0);
    Ok((&[], NALUnit::EndOfStream()))
}

fn parse_nal_unit_end_of_sequence(input: &[u8]) -> IResult<&[u8], NALUnit> {
    let (input, _) = bytes::complete::tag(&[NALUnitType::EndOfSequence as u8][..])(input)?;
    assert_eq!(input.len(), 0);
    Ok((&[], NALUnit::EndOfSequence()))
}

fn parse_nal_unit_unknown(input: &[u8]) -> IResult<&[u8], NALUnit> {
    let (rest, nal_type) = bytes::complete::take(1usize)(input)?;
    Ok((&[], NALUnit::Unknown(nal_type[0], rest.to_vec())))
}

fn parse_nal_unit(input: &[u8]) -> IResult<&[u8], NALUnit> {
    let (input, _) = branch::alt((bytes::streaming::tag(NAL_BOUNDARY), bytes::streaming::tag(NAL_BOUNDARY_WITH_PREFIX)))(input)?;
    let (input, rawnal) = bytes::streaming::take_until(NAL_BOUNDARY)(input)?;
    let rawnal = if rawnal.last() == Some(NAL_BOUNDARY_OPTIONAL_PREFIX) { &rawnal[..rawnal.len()-1] } else { rawnal };
    let (empty, nal_unit) = branch::alt((
        parse_nal_unit_non_idr,
        parse_nal_unit_idr,
        parse_nal_unit_sei,
        parse_nal_unit_sps,
        parse_nal_unit_pps,
        parse_nal_unit_aud,
        parse_nal_unit_end_of_sequence,
        parse_nal_unit_end_of_stream,
        parse_nal_unit_unknown,
    ))(rawnal)?;
    assert_eq!(empty.len(), 0);
    Ok((input, nal_unit))
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

fn read_more_data_from_iterator(iterator: &mut dyn Iterator<Item=Vec<u8>>, unparsed_data: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    // reading directly from file would lead to one less data-copy operation, but this abstraction
    // is clearer.
    if let Some(new_data) = iterator.next() {
        unparsed_data.extend(&new_data);
        Ok(())
    } else {
        Err("EOF")?
    }
}

pub struct NALUnitIterator {
    input_iterator: Box<dyn Iterator<Item=Vec<u8>>>,
    unparsed_data: Vec<u8>
}


impl NALUnitIterator {
    pub fn new(input_iterator: Box<dyn Iterator<Item=Vec<u8>>>) -> NALUnitIterator {
        return Self {
            input_iterator,
            unparsed_data: vec![]
        }
    }
}

impl Iterator for NALUnitIterator {
    type Item = NALUnit;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match parse_nal_unit(&self.unparsed_data) {
                Ok((new_unparsed_data, return_value)) => {
                    self.unparsed_data = new_unparsed_data.to_vec();
                    return Some(return_value);
                }
                Err(Err::Incomplete(_)) => {
                    // println!("More data needed");
                    match read_more_data_from_iterator(&mut self.input_iterator, &mut self.unparsed_data) {
                        Ok(()) => {}
                        Err(_) => {
                            if self.unparsed_data.len() == 0 {
                                println!("Done");
                                return None;
                            } else {
                                println!("There are {} bytes remaining", self.unparsed_data.len() );
                                return None;
                            }
                        }
                    }
                }
                Err(e) => {
                    panic!("Parse error: {}", e);
                }
            };
        }
    }
}
