use super::stream::{stream, Stream, PartialStream};
use std::fmt;

const SHORT_NAL_BOUNDARY: &[u8] = b"\x00\x00\x01";
const LONG_NAL_BOUNDARY: &[u8] = b"\x00\x00\x00\x01";
const EMULATION_PREVENTION_BYTES: &[u8] = b"\x00\x00\x03"; 

use winnow::{binary::{bits,self}, combinator, error, token, IResult, Parser };

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

fn parse_till_nal_unit_end(input: PartialStream) -> IResult<PartialStream, Vec<u8>> {
    let (input, data) = combinator::alt((
        Parser::complete_err(token::take_until0(LONG_NAL_BOUNDARY)),
        token::take_until0(SHORT_NAL_BOUNDARY),
        combinator::rest,
    ))
    .parse_next(input)?;
    let datastream = stream(data);
    let (suffix, mut parts): (Stream, Vec<&[u8]>) = combinator::repeat(
        0.., (
            token::take_until0::<_, _, ()>(EMULATION_PREVENTION_BYTES),
            EMULATION_PREVENTION_BYTES,
            ).map(|x| x.0)).parse_next(datastream).unwrap();
    parts.push(suffix);
    Ok((input, parts.join(&[0_u8; 2][..])))
}

pub trait NALUnitBase {
    fn parse(input: Stream) -> IResult<Stream, NALUnit>;
}

pub trait KnownNALUnit {
    const NU_TYPE: u8;

    fn parse_idc_ref_and_check_nutype(input: Stream) -> IResult<Stream, u8> {
        let nutype_parser = bits::tag(Self::NU_TYPE, 5_usize);
        let (input, (_, ref_idc, _nutype)) = bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
            bits::tag(0_u8, 1_usize),
            bits::take(2_usize),
            nutype_parser,
        ))
        .parse_next(input)?;
        Ok((input, ref_idc))
    }
    fn parse(input: Stream) -> IResult<Stream, NALUnit>;
}

pub struct NonIDRPictureNU {
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}

impl KnownNALUnit for NonIDRPictureNU {
    const NU_TYPE: u8 = 1;
    fn parse(input: Stream) -> IResult<Stream, NALUnit> {
        let (input, ref_idc) = Self::parse_idc_ref_and_check_nutype(input)?;
        let (input, rest) = combinator::rest.parse_next(input)?;
        Ok((
            input,
            NALUnit::NonIDRPicture(Self {
                ref_idc,
                rest: rest.to_vec(),
            }),
        ))
    }
}

impl fmt::Debug for NonIDRPictureNU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "NonIDRPicture: {} {:x?}",
            self.ref_idc,
            &self.rest[..(16.min(self.rest.len()))]
        )
    }
}

pub struct IDRPictureNU {
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}

impl KnownNALUnit for IDRPictureNU {
    const NU_TYPE: u8 = 5;

    fn parse(input: Stream) -> IResult<Stream, NALUnit> {
        let (input, ref_idc) = Self::parse_idc_ref_and_check_nutype(input)?;
        let (input, rest) = combinator::rest.parse_next(input)?;
        Ok((
            input,
            NALUnit::IDRPicture(Self {
                ref_idc,
                rest: rest.to_vec(),
            }),
        ))
    }
}

impl fmt::Debug for IDRPictureNU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IDRPicture: {} {:x?}",
            self.ref_idc,
            &self.rest[..(16.min(self.rest.len()))]
        )
    }
}

pub struct UnknownNU {
    pub nal_unit_type: u8,
    pub ref_idc: u8,
    pub rest: Vec<u8>,
}

impl NALUnitBase for UnknownNU {
    fn parse(input: Stream) -> IResult<Stream, NALUnit> {
        let (input, (ref_idc, nal_unit_type)) =
            bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
                bits::take(3_usize),
                bits::take(5_usize),
            ))
            .parse_next(input)?;
        let (input, rest) = combinator::rest.parse_next(input)?;
        Ok((
            input,
            NALUnit::Unknown(Self {
                nal_unit_type,
                ref_idc,
                rest: rest.to_vec(),
            }),
        ))
    }
}

impl fmt::Debug for UnknownNU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "UnknownNALUntit: {}, {} {:x?}",
            self.nal_unit_type,
            self.ref_idc,
            &self.rest[..(16.min(self.rest.len()))]
        )
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

pub fn parse_nal_unit(input: PartialStream) -> IResult<PartialStream, NALUnit> {
    let (input, _) = combinator::alt((LONG_NAL_BOUNDARY, SHORT_NAL_BOUNDARY)).parse_next(input)?;
    let (input, nudata) = parse_till_nal_unit_end(input)?;
    let nudata = stream(&nudata[..]);
    let (nudata, firstbyte) = combinator::peek(binary::u8::<_, ()>).parse_next(nudata).unwrap();
    let nal_unit = match firstbyte & 0b0001_1111_u8 {
        IDRPictureNU::NU_TYPE => IDRPictureNU::parse.parse(nudata),
        NonIDRPictureNU::NU_TYPE => NonIDRPictureNU::parse.parse(nudata),
        _ => UnknownNU::parse.parse(nudata),
    }.unwrap();
    Ok((input, nal_unit))
}
