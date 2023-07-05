use winnow::{Bytes, stream::Partial};

pub type Stream<'i> = Partial<&'i Bytes>;

pub fn stream(b: &[u8]) -> Stream<'_> {
    Stream::new(Bytes::new(b))
}
