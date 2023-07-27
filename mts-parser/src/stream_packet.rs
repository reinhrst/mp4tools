use super::crc;
use super::stream::{partialstream, PartialStream};
use core::num::NonZeroUsize;
use std::fmt;
use winnow::{
    binary::{self, bits},
    combinator, error,
    stream::StreamIsPartial,
    token, IResult, Parser,
};

macro_rules! marker_bit {
    () => {
        bits::tag(0b1_u8, 1_usize).void()
    }
}

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
    UnsupportedPSITable(PSISharedTableInfo, Vec<u8>),
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
                        marker_bit!(),
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
            return Ok((input, StreamPacket::UnsupportedPSITable(psi_data, body.to_vec())));
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

#[derive(Debug)]
pub struct PESExtension {
    pub pes_private_data: Option<Vec<u8>>,
    pub pack_header_field: Option<Vec<u8>>,
    pub program_packet_sequence_counter: Option<(u8, bool, u8)>,
    pub p_std_buffer: Option<(bool, u8)>,
    pub pes_extension_data: Option<Vec<u8>>,
}

impl PESExtension {
    pub fn parse(input: PartialStream) -> IResult<PartialStream, Self> {
        let (
            input,
            (
                pes_private_data_flag,
                pack_header_field_flag,
                program_packet_sequence_counter_flag,
                p_std_buffer_flag,
                _,
                pes_extension_flag_2,
            ),
        ) = bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
            bits::bool,
            bits::bool,
            bits::bool,
            bits::bool,
            bits::take::<_, u8, _, _>(3_usize),
            bits::bool,
        ))
        .parse_next(input)?;

        let (input, pes_private_data) = combinator::cond(
            pes_private_data_flag,
            token::take(16_usize).output_into::<Vec<u8>>(),
        )
        .parse_next(input)?;

        let (input, pack_header_field) = combinator::cond(
            pack_header_field_flag,
            binary::length_data(binary::be_u8).output_into::<Vec<u8>>(),
        )
        .parse_next(input)?;

        let (input, program_packet_sequence_counter) = combinator::cond(
            program_packet_sequence_counter_flag,
            bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
                marker_bit!(),
                bits::take::<_, u8, _, _>(7_usize),
                marker_bit!(),
                bits::bool,
                bits::take::<_, u8, _, _>(6_usize),
            ))
            .map(|val| (val.1, val.3, val.4)),
        )
        .parse_next(input)?;

        let (input, p_std_buffer) = combinator::cond(
            p_std_buffer_flag,
            bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
                bits::tag(0b01_u8, 2_usize),
                bits::bool,
                bits::take::<_, u8, _, _>(13_usize),
            ))
            .map(|val| (val.1, val.2)),
        )
        .parse_next(input)?;

        let (input, pes_extension_data) = combinator::cond(
            pes_extension_flag_2,
            binary::length_data(bits::bits::<_, _, error::Error<(_, usize)>, _, _>(
                combinator::preceded(
                    marker_bit!(),
                    bits::take::<_, u8, _, _>(7_usize),
                ),
            ))
            .output_into::<Vec<u8>>(),
        )
        .parse_next(input)?;

        combinator::eof.parse_next(input)?;

        Ok((
            input,
            Self {
                pes_private_data,
                pack_header_field,
                program_packet_sequence_counter,
                p_std_buffer,
                pes_extension_data,
            },
        ))
    }
}

#[derive(Debug)]
pub struct PESHeader {
    pub scrambling_control: u8,
    pub priority: bool,
    pub data_alignment_indicator: bool,
    pub copyright: bool,
    pub is_original: bool,
    pub pts: Option<u64>,
    pub dts: Option<u64>,
    pub escr: Option<(u64, u16)>,
    pub es_rate: Option<u32>,
    pub dsm_trick_mode: Option<(u8, u8)>,
    pub additional_copy_info: Option<u8>,
    pub previous_pes_packet_crc: Option<u16>,
    pub pes_extension: Option<PESExtension>,
}

impl PESHeader {
    const PADDING: u8 = 0xFF;
    pub fn parse(input: PartialStream) -> IResult<PartialStream, Self> {
        let (
            input,
            (
                scrambling_control,
                priority,
                data_alignment_indicator,
                copyright,
                is_original,
                pts_flag,
                dts_flag,
                escr_flag,
                es_rate_flag,
                dsm_trick_mode_flag,
                additional_copy_info_flag,
                crc_flag,
                pes_extension_flag,
            ),
        ) = bits::bits::<_, _, error::Error<(_, usize)>, _, _>(combinator::preceded(
            bits::tag(2_u8, 2_usize),
            (
                bits::take(2_usize),
                bits::bool,
                bits::bool,
                bits::bool,
                bits::bool,
                bits::bool,
                bits::bool,
                bits::bool,
                bits::bool,
                bits::bool,
                bits::bool,
                bits::bool,
                bits::bool,
            ),
        ))
        .parse_next(input)?;

        let (input, data) = binary::length_data(binary::be_u8).parse_next(input)?;
        let data_stream = partialstream(data, true);
        let (data_stream, pts) = combinator::cond(
            pts_flag,
            bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
                bits::tag(0b0010_u8 | dts_flag as u8, 4_usize),
                bits::take::<_, u64, _, _>(3_usize),
                marker_bit!(),
                bits::take::<_, u64, _, _>(15_usize),
                marker_bit!(),
                bits::take::<_, u64, _, _>(15_usize),
                marker_bit!(),
            ))
            .map(|val| val.1 << 30 | val.3 << 15 | val.5),
        )
        .parse_next(data_stream)?;
        let (data_stream, dts) = combinator::cond(
            dts_flag,
            bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
                bits::tag(0b0001_u8, 4_usize),
                bits::take::<_, u64, _, _>(3_usize),
                marker_bit!(),
                bits::take::<_, u64, _, _>(15_usize),
                marker_bit!(),
                bits::take::<_, u64, _, _>(15_usize),
                marker_bit!(),
            ))
            .map(|val| val.1 << 30 | val.3 << 15 | val.5),
        )
        .parse_next(data_stream)?;
        let (data_stream, escr) = combinator::cond(
            escr_flag,
            bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
                bits::take::<_, u8, _, _>(2_usize).void(),
                bits::take::<_, u64, _, _>(3_usize),
                marker_bit!(),
                bits::take::<_, u64, _, _>(15_usize),
                marker_bit!(),
                bits::take::<_, u64, _, _>(15_usize),
                marker_bit!(),
                bits::take::<_, u16, _, _>(9_usize),
                marker_bit!(),
            ))
            .map(|val| (val.1 << 30 | val.3 << 15 | val.5, val.7)),
        )
        .parse_next(data_stream)?;
        let (data_stream, es_rate) = combinator::cond(
            es_rate_flag,
            bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
                marker_bit!(),
                bits::take::<_, u32, _, _>(22_usize),
                marker_bit!(),
            ))
            .map(|val| val.1),
        )
        .parse_next(data_stream)?;
        let (data_stream, dsm_trick_mode) = combinator::cond(
            dsm_trick_mode_flag,
            bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
                bits::take::<_, u8, _, _>(3_usize),
                bits::take::<_, u8, _, _>(5_usize),
            )),
        )
        .parse_next(data_stream)?;
        let (data_stream, additional_copy_info) = combinator::cond(
            additional_copy_info_flag,
            bits::bits::<_, _, error::Error<(_, usize)>, _, _>((
                marker_bit!(),
                bits::take::<_, u8, _, _>(7_usize),
            ))
            .map(|val| val.1),
        )
        .parse_next(data_stream)?;
        let (data_stream, previous_pes_packet_crc) =
            combinator::cond(crc_flag, binary::be_u16).parse_next(data_stream)?;
        let (data_stream, pes_extension) =
            combinator::cond(pes_extension_flag, PESExtension::parse).parse_next(data_stream)?;

        combinator::opt(token::take_while(data_stream.len(), Self::PADDING)).parse_next(data_stream)?;

        Ok((
            input,
            Self {
                scrambling_control,
                priority,
                data_alignment_indicator,
                copyright,
                is_original,
                pts,
                dts,
                escr,
                es_rate,
                dsm_trick_mode,
                additional_copy_info,
                previous_pes_packet_crc,
                pes_extension,
            },
        ))
    }
}

pub struct PESPacket {
    pub stream_id: u8,
    pub header: Option<PESHeader>,
    pub data: Vec<u8>,
}

impl PESPacket {
    const START: &[u8] = b"\x00\x00\x01";
    const STREAM_IDS_WITHOUT_HEADER: [u8;8] = [
        0b1011_1100_u8, // program_stream_map
        0b1011_1110, // padding stream
        0b1011_1111, // private stream 2
        0b1111_0000, // ECM
        0b1111_0001, // EMM 
        0b1111_0010, // ISO/IEC 13818- 6_DSMCC_stream
        0b1111_1000, //ITU-T Rec. H.222.1 type E
        0b1111_1111, // program stream directory

    ];
    pub fn parse(input: PartialStream) -> IResult<PartialStream, StreamPacket> {
        let (input, (_, stream_id)) = (Self::START, binary::be_u8).parse_next(input)?;
        let (input, packet_len) = binary::be_u16.parse_next(input)?;
        if packet_len == 0 && input.is_partial() {
            return Err(error::ErrMode::Incomplete(error::Needed::Unknown));
        }
        if packet_len > 0 && input.len() < packet_len as usize {
            return Err(error::ErrMode::Incomplete(error::Needed::Size(
                NonZeroUsize::new(packet_len as usize - input.len()).unwrap(),
            )));
        }
        let (input, packet) = match packet_len {
            0 => combinator::rest.parse_next(input)?,
            _ => token::take(packet_len).parse_next(input)?,
        };
        let packet_stream = partialstream(packet, true);

        let (packet_stream, header) = combinator::cond(
            !Self::STREAM_IDS_WITHOUT_HEADER.contains(&stream_id),
            PESHeader::parse,
        )
        .parse_next(packet_stream)?;
        let data = packet_stream.into_inner().to_vec();

        Ok((
            input,
            StreamPacket::PES(PESPacket {
                stream_id,
                header,
                data,
            }),
        ))
    }
}

impl fmt::Debug for PESPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PESPacket(stream_id=0x{:x}, header={:?}, data({}) = {:x?}...)",
            self.stream_id,
            self.header,
            self.data.len(),
            &self.data[..20.min(self.data.len())],
        )
    }
}
