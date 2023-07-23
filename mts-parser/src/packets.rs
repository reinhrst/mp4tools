// see https://en.wikipedia.org/wiki/MPEG_transport_stream#Packet
use super::stream::PartialStream;
use std::fmt;
use winnow::{
    binary::{self, bits},
    combinator, error, token, IResult, Parser,
};

#[derive(Debug)]
pub struct PCR {
    pub base: u64,
    pub reserved: u8,
    pub extension: u16,
}

impl PCR {
    fn parse(input: PartialStream) -> IResult<PartialStream, Self> {
        let (input, (pcr_plus_two_bytes, _)) = (
            combinator::peek(binary::be_u64),
            token::take(6_usize)
        ).parse_next(input)?;

        let data = pcr_plus_two_bytes >> 16;
        Ok((input, Self {
            base: data >> 15,
            reserved: ((data >> 9) & 0x3f) as u8,
            extension: (data & 0x1ff) as u16,
        }))
    }
}

#[derive(Debug)]
pub struct AdaptationExtension {
    pub data: Vec<u8>
}

impl AdaptationExtension{
    fn parse(input: PartialStream) -> IResult<PartialStream, Self> {
        let (input, data) = binary::length_data(binary::be_u8).parse_next(input)?;
        Ok((input, Self{data: data.to_vec()}))
    }
}

#[derive(Debug)]
pub struct AdaptationField{
    pub discontinuity_indicator: bool,
    pub random_access_indicator: bool,
    pub elementary_stream_priority_indicator: bool,
    pub pcr: Option<PCR>,
    pub opcr: Option<PCR>,
    pub splice_countdown: Option<i8>,
    pub transport_private_data: Option<Vec<u8>>,
    pub adaption_extension: Option<AdaptationExtension>,
    pub padding: usize,
}

impl AdaptationField{
    pub fn parse(input: PartialStream) -> IResult<PartialStream, Self> {
        binary::length_value(binary::be_u8, Self::parse_length_limited).parse_next(input)
    }

    fn parse_length_limited(input: PartialStream) -> IResult<PartialStream, Self> {
        let (input, (di, rai, espi, pcr_flag, opcr_flag, spf, tpdf, afef)) = 
        bits::bits::<_, (bool, bool, bool, bool, bool, bool, bool, bool), error::Error<(_, usize)>, _, _>((
            bits::bool,
            bits::bool,
            bits::bool,
            bits::bool,
            bits::bool,
            bits::bool,
            bits::bool,
            bits::bool,
        )).parse_next(input)?;
        let (input, pcr) = combinator::cond(pcr_flag, PCR::parse).parse_next(input)?;
        let (input, opcr) = combinator::cond(opcr_flag, PCR::parse).parse_next(input)?;
        let (input, splice_countdown) = combinator::cond(spf, binary::be_i8).parse_next(input)?;
        let (input, transport_private_data) = combinator::cond(tpdf, binary::length_data(binary::be_u8).output_into::<Vec<u8>>()).parse_next(input)?;
        let (input, adaption_extension) = combinator::cond(afef, AdaptationExtension::parse).parse_next(input)?;
        let (input, rest) = token::take_while(0.., 0xFF_u8).parse_next(input)?;
        Ok((input, Self {
            discontinuity_indicator: di,
            random_access_indicator: rai,
            elementary_stream_priority_indicator: espi,
            pcr,
            opcr,
            splice_countdown,
            transport_private_data,
            adaption_extension,
            padding: rest.len(),
        }))
    }
}

pub struct Payload {
    data: Vec<u8>
}

impl From<&[u8]> for Payload {
    fn from(value: &[u8]) -> Self {
        Self {
            data: value.to_vec(),
        }
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Payload({}): {:x?}...",
            self.data.len(),
            &self.data[..20.min(self.data.len())],
        )
    }
}


pub struct Packet {
    pub copy_protection: u8,
    pub arrival_timestamp: u32,
    pub transport_error_indicator: bool,
    pub payload_unit_start_indicator: bool,
    pub transport_priority: bool,
    pub pid: u16,
    pub transport_scrambling_control: u8,
    pub continuity_counter: u8,
    pub adaptation_field: Option<AdaptationField>,
    pub payload_data: Option<Payload>,
}

impl Packet {
    const PACKET_LENGTH: usize = 192;

    pub fn parse(input: PartialStream) -> IResult<PartialStream, Self> {
        binary::length_value(combinator::success(Self::PACKET_LENGTH), Self::parse_length_limited).parse_next(input)
    }

    fn parse_length_limited(input: PartialStream) -> IResult<PartialStream, Packet> {
        let (input, (copy_protection, arrival_timestamp)) =
            bits::bits::<_, (u8, u32), error::Error<(_, usize)>, _, _>((
                bits::take(2_usize),
                bits::take(30_usize),
            ))
            .parse_next(input)?;
        let (input, _) = b'G'.parse_next(input)?;
        let (input, (transport_error_indicator, payload_unit_start_indicator, transport_priority, pid, transport_scrambling_control, has_adaptation_field, has_payload, continuity_counter)) =
            bits::bits::<_, (bool, bool, bool, u16, u8, bool, bool, u8), error::Error<(_, usize)>, _, _>((
                bits::bool,
                bits::bool,
                bits::bool,
                bits::take(13_usize),
                bits::take(2_usize),
                bits::bool,
                bits::bool,
                bits::take(4_usize),
            ))
            .parse_next(input)?;
        let(input, adaptation_field) = combinator::cond(has_adaptation_field, AdaptationField::parse).parse_next(input)?;
        let(input, payload_data) = combinator::cond(has_payload, combinator::rest.output_into::<Payload>()).parse_next(input)?;
        Ok((input, Self {
            copy_protection,
            arrival_timestamp,
            transport_error_indicator,
            payload_unit_start_indicator,
            transport_priority,
            pid,
            transport_scrambling_control,
            continuity_counter,
            adaptation_field,
            payload_data,
        }))
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {} {:x} {} {} {:?} {:?}\n",
            self.copy_protection,
            self.arrival_timestamp,
            self.transport_error_indicator,
            self.payload_unit_start_indicator,
            self.transport_priority,
            self.pid,
            self.transport_scrambling_control,
            self.continuity_counter,
            self.adaptation_field,
            self.payload_data,
        )
    }
}

