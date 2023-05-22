use clap::Parser;
use h264_parser::{FileIterator, NALUnit, NALUnitIterator};
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
    let file_iterator = FileIterator::new(file);
    let nal_unit_iterator = NALUnitIterator::new(Box::new(file_iterator));
    let mut framecnt = 0;
    for nal_unit in nal_unit_iterator {
        match nal_unit {
            NALUnit::IDR(_) | NALUnit::NonIDR(_) => {
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
            NALUnit::IDR(_) => {
                print!("R")
            }
            NALUnit::NonIDR(ref non_idr) => match non_idr.ref_idc {
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
