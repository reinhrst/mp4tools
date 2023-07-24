use super::crc;
use super::stream::{partialstream, PartialStream};
use std::fmt;
use winnow::{
    binary::{self, bits},
    combinator, error,
    stream::StreamIsPartial,
    token, IResult, Parser,
};

#[derive(Debug)]
pub struct PATTableEntry {
    pub program_number: u16,
    pub program_map_pid: u16,
}

impl PATTableEntry {
    pub fn parse(input: PartialStream) -> IResult<PartialStream, Self> {
        let (input, (program_number, program_map_pid)) = (
            binary::be_u16,
            bits::bits::<_, u16, error::Error<(_, usize)>, _, _>(
                (bits::tag(7, 3_usize), bits::take(13_usize)).map(|val| val.1),
            ),
        )
            .parse_next(input)?;
        Ok((
            input,
            PATTableEntry {
                program_number,
                program_map_pid,
            },
        ))
    }
}

#[derive(Debug)]
pub enum StreamPacket {
    PAT(PATTable),
    PMT(PMTTable),
    PES(PESPacket),
    Unknown(PSISharedTableInfo, Vec<u8>),
}

#[derive(Debug)]
pub struct PSISharedTableInfo {
    pub table_id: u8,
    pub table_id_extension: u16,
    pub version_number: u8,
    pub current: bool,
    pub section_number: u8,
    pub last_section_number: u8,
}

impl PSISharedTableInfo {
    const PADDING: u8 = 0xFF;
    pub fn parse(input: PartialStream) -> IResult<PartialStream, (Self, &[u8])> {
        let (input, (((table_id, rest), table_data), crc32)) = (
            (
                binary::be_u8,
                binary::length_data(bits::bits::<_, u16, error::Error<(_, usize)>, _, _>(
                    (
                        bits::tag(1_u8, 1_usize),
                        bits::take(1_usize),
                        bits::tag(3_u8, 2_usize),
                        bits::tag(0_u8, 2_usize),
                        bits::take(10_usize),
                    )
                        .map(|val: (_, u8, _, _, u16)| val.4 - 4),
                )),
            )
                .with_recognized(),
            binary::be_u32,
        )
            .parse_next(input)?;
        let mycrc = crc::crc(table_data);
        assert!(mycrc == crc32);
        let (input, _) = Self::eat_up_padding(input)?;

        let table_input = partialstream(rest, true);
        let (
            table_input,
            (
                table_id_extension,
                (_, version_number, current),
                section_number,
                last_section_number,
                rest,
            ),
        ) = (
            binary::be_u16,
            bits::bits::<_, (_, u8, bool), error::Error<(_, usize)>, _, _>((
                bits::tag(0x3_u8, 2_usize),
                bits::take(5_usize),
                bits::bool,
            )),
            binary::be_u8,
            binary::be_u8,
            combinator::rest,
        )
            .parse_next(table_input)?;
        assert!(table_input.len() == 0);

        Ok((
            input,
            (
                Self {
                    table_id,
                    table_id_extension,
                    version_number,
                    current,
                    section_number,
                    last_section_number,
                },
                rest,
            ),
        ))
    }

    pub fn eat_up_padding(input: PartialStream) -> IResult<PartialStream, ()> {
        let (input, _) =
            combinator::opt(token::take_while(input.len(), Self::PADDING)).parse_next(input)?;
        Ok((input, ()))
    }
}

pub trait Parsable {
    const TABLE_ID: u8;
    fn parse(input: PartialStream) -> IResult<PartialStream, StreamPacket> {
        let (input, (psi_data, body)) = PSISharedTableInfo::parse(input)?;
        if psi_data.table_id != Self::TABLE_ID {
            return Ok((input, StreamPacket::Unknown(psi_data, body.to_vec())));
        }
        let bodyinput = partialstream(body, true);
        let (bodyinput, result) = Self::parse_body(bodyinput, psi_data)?;
        assert!(bodyinput.len() == 0);

        Ok((input, result))
    }

    fn parse_body(
        input: PartialStream,
        psi_data: PSISharedTableInfo,
    ) -> IResult<PartialStream, StreamPacket>;
}

#[derive(Debug)]
pub struct PATTable {
    pub psi_data: PSISharedTableInfo,
    //PAT-fields:
    pub entries: Vec<PATTableEntry>,
}

impl Parsable for PATTable {
    const TABLE_ID: u8 = 0;
    fn parse_body(
        input: PartialStream,
        psi_data: PSISharedTableInfo,
    ) -> IResult<PartialStream, StreamPacket> {
        let (input, entries) = combinator::repeat(1.., PATTableEntry::parse).parse_next(input)?;
        Ok((input, StreamPacket::PAT(PATTable { psi_data, entries })))
    }
}

#[derive(Debug)]
pub struct ElementaryStreamInfo {
    pub stream_type: u8,
    pub pid: u16,
    pub descriptors: Vec<u8>,
}

impl ElementaryStreamInfo {
    pub fn parse(input: PartialStream) -> IResult<PartialStream, Self> {
        let (input, (stream_type, pid, descriptors)) = (
            binary::be_u8,
            bits::bits::<_, u16, error::Error<(_, usize)>, _, _>(
                (bits::tag(7, 3_usize), bits::take(13_usize)).map(|val| val.1),
            ),
            binary::length_data(bits::bits::<_, u16, error::Error<(_, usize)>, _, _>(
                (
                    bits::tag(0xF, 4_usize),
                    bits::tag(0, 2_usize),
                    bits::take(10_usize),
                )
                    .map(|val| val.2),
            ))
            .output_into::<Vec<u8>>(),
        )
            .parse_next(input)?;
        Ok((
            input,
            Self {
                stream_type,
                pid,
                descriptors,
            },
        ))
    }
}

#[derive(Debug)]
pub struct PMTTable {
    pub psi_data: PSISharedTableInfo,
    pub pcr_pid: u16,
    pub program_descriptiors: Vec<u8>,
    pub elementary_stream_info_data: Vec<ElementaryStreamInfo>,
}

impl Parsable for PMTTable {
    const TABLE_ID: u8 = 2;
    fn parse_body(
        input: PartialStream,
        psi_data: PSISharedTableInfo,
    ) -> IResult<PartialStream, StreamPacket> {
        let (input, (pcr_pid, program_descriptiors, elementary_stream_info_data)) = (
            bits::bits::<_, u16, error::Error<(_, usize)>, _, _>(
                (bits::tag(7, 3_usize), bits::take(13_usize)).map(|val| val.1),
            ),
            binary::length_data(bits::bits::<_, u16, error::Error<(_, usize)>, _, _>(
                (
                    bits::tag(0xF, 4_usize),
                    bits::tag(0, 2_usize),
                    bits::take(10_usize),
                )
                    .map(|val| val.2),
            ))
            .output_into::<Vec<u8>>(),
            combinator::repeat(0.., ElementaryStreamInfo::parse),
        )
            .parse_next(input)?;

        Ok((
            input,
            StreamPacket::PMT(PMTTable {
                psi_data,
                pcr_pid,
                program_descriptiors,
                elementary_stream_info_data,
            }),
        ))
    }
}

pub struct PESPacket {
    data: Vec<u8>,
}

impl PESPacket {
    // const START: [u8; 3] = [0, 0, 1];
    pub fn parse(input: PartialStream) -> IResult<PartialStream, StreamPacket> {
        let (input, rest) = if input.is_partial() {
            token::take(input.len() + 1).parse_next(input)?
        } else {
            token::take(input.len()).parse_next(input)?
        };
        Ok((
            input,
            StreamPacket::PES(PESPacket {
                data: rest.to_vec(),
            }),
        ))
    }
}

impl fmt::Debug for PESPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PESPacket({}): {:x?}...",
            self.data.len(),
            &self.data[..20.min(self.data.len())],
        )
    }
}
