use winnow::{Bytes, stream::{Partial, StreamIsPartial}};

pub type PartialStream<'i> = Partial<&'i Bytes>;

pub fn partialstream(b: &[u8], complete: bool) -> PartialStream<'_> {
    let mut mystream = PartialStream::new(Bytes::new(b));
    if complete {
        let _ = mystream.complete();
    };
    mystream
}

pub type Stream<'i> = &'i Bytes;

pub fn stream(b: &[u8]) -> Stream {
    Bytes::new(b)
}
