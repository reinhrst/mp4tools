use super::stream::PartialStream;
use winnow::{
    binary::{self, bits},
    combinator, token, error, IResult, Parser,
};

#[derive(Debug)]
pub struct PATTable {
    pub table_id_extension: u16,
    pub version_number: u8,
    pub current: bool,
    pub section_number: u8,
    pub last_section_number: u8,
    //PAT-fields:
    pub program_number: u16,
    pub program_map_pid: u16,
}

impl PATTable {
    const PAT_TABLE_ID: u8 = 0;
    const PADDING: u8 = 0xFF;
    pub fn parse(input: PartialStream) -> IResult<PartialStream, Self> {
        let (input, (_, (table_id_extension, (_, version_number, current), section_number, last_section_number, program_number, program_map_pid, _crc32))) = (
            Self::PAT_TABLE_ID,
            binary::length_value(
                    bits::bits::<_, u16, error::Error<(_, usize)>, _, _>((
                        bits::tag(1, 1_usize),
                        bits::tag(0, 1_usize),
                        bits::tag(3, 2_usize),
                        bits::tag(0, 2_usize),
                        bits::take(10_usize),
                    ).map(|val| val.4)),
                (
                    binary::be_u16,
                    bits::bits::<_, (_, u8, bool), error::Error<(_, usize)>, _, _>((
                        bits::tag(0x3_u8, 2_usize),
                        bits::take(5_usize),
                        bits::bool,
                    )),
                    binary::be_u8,
                    binary::be_u8,
                    binary::be_u16,
                    bits::bits::<_, u16, error::Error<(_, usize)>, _, _>((
                        bits::tag(7, 3_usize),
                        bits::take(13_usize),
                    ).map(|val| val.1)),
                    binary::be_u32,
                )),
            ).parse_next(input)?;
        let (input, _) = Self::eat_up_padding(input)?;

        Ok((input, PATTable {
            table_id_extension,
            version_number,
            current,
            section_number,
            last_section_number,
            program_number,
            program_map_pid,
        }))
    }

    pub fn eat_up_padding(input: PartialStream) -> IResult<PartialStream, ()> {
        let (input, _) = combinator::opt(token::take_while(input.len(), Self::PADDING)).parse_next(input)?;
        Ok((input, ()))
    }
}



