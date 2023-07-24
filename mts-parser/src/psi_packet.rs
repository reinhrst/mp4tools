use super::crc;
use super::stream::{partialstream, PartialStream};
use winnow::{
    binary::{self, bits},
    combinator, error, token, IResult, Parser,
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
        let (
            input,
            (
                (
                    (
                        table_id,
                        (
                            table_id_extension,
                            (_, version_number, current),
                            section_number,
                            last_section_number,
                            rest,
                        ),
                    ),
                    table_data,
                ),
                crc32,
            ),
        ) = (
            (
                binary::be_u8,
                binary::length_value(
                    bits::bits::<_, u16, error::Error<(_, usize)>, _, _>(
                        (
                            bits::tag(1_u8, 1_usize),
                            bits::tag(0_u8, 1_usize),
                            bits::tag(3_u8, 2_usize),
                            bits::tag(0_u8, 2_usize),
                            bits::take(10_usize),
                        )
                            .map(|val: (_, _, _, _, u16)| val.4 - 4),
                    ),
                    (
                        binary::be_u16,
                        bits::bits::<_, (_, u8, bool), error::Error<(_, usize)>, _, _>((
                            bits::tag(0x3_u8, 2_usize),
                            bits::take(5_usize),
                            bits::bool,
                        )),
                        binary::be_u8,
                        binary::be_u8,
                        combinator::rest,
                    ),
                ),
            )
                .with_recognized(),
            binary::be_u32,
        )
            .parse_next(input)?;
        let (input, _) = Self::eat_up_padding(input)?;

        let mycrc = crc::crc(table_data);
        assert!(mycrc == crc32);

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

#[derive(Debug)]
pub struct PATTable {
    pub psi_data: PSISharedTableInfo,
    //PAT-fields:
    pub entries: Vec<PATTableEntry>,
}

impl PATTable {
    const PAT_TABLE_ID: u8 = 0;
    pub fn parse(input: PartialStream) -> IResult<PartialStream, Self> {
        let (input, (psi_data, body)) = PSISharedTableInfo::parse(input)?;
        assert!(psi_data.table_id == Self::PAT_TABLE_ID);
        let bodyinput = partialstream(body, true);
        let (bodyinput, entries) =
            combinator::repeat(1.., PATTableEntry::parse).parse_next(bodyinput)?;
        assert!(bodyinput.len() == 0);

        Ok((input, PATTable { psi_data, entries }))
    }
}
