use clap::Parser;
use h264_parser::{nalunits::NALUnit, NALUnitIterator};
use mts_parser::{packets::Packet, MTSPacketIterator, ElementIterator};
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Filename to process
    input: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    println!("Hello {}!", args.input.to_str().expect("Not unicode path"));
    let file = File::open(args.input)?;
    parse_mts(file)
}

fn parse_mts(file: File) -> Result<(), Box<dyn Error>> {
    let packet_iterator = MTSPacketIterator::new(Box::new(file));
    let element_iterator = ElementIterator::new(packet_iterator);
    for element in element_iterator {
        println!("{:?}", element);
    }
    Ok(())
}

fn parse_h264(file: File) -> Result<(), Box<dyn Error>> {
    let nal_unit_iterator = NALUnitIterator::new(Box::new(file));
    let mut framecnt = 0;
    for nal_unit in nal_unit_iterator {
        match nal_unit {
            NALUnit::IDRPicture(_) | NALUnit::NonIDRPicture(_) => {
                framecnt += 1;
                if framecnt % 24 == 0 {
                    println!("")
                }
                if framecnt % 2 == 0 {
                    continue;
                }
            }
            _ => ()
        }
        match nal_unit {
            NALUnit::Unknown(_nu) => {
                // println!("{:?}", _nu);
            }
            NALUnit::IDRPicture(_) => {
                print!("R")
            }
            NALUnit::NonIDRPicture(ref non_idr) => match non_idr.ref_idc {
                3 => print!("I"),
                2 => print!("P"),
                0 => print!("B"),
                x => print!("??{}??", x),
            },
            _ => (),
        }
    }
    Ok(())
}
