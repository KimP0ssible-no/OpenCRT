//! Session character encodings other than UTF-8 (Session Options > Terminal):
//! host output is decoded to UTF-8 for the terminal, typed text encoded back.

use encoding_rs::{CoderResult, Decoder, EncoderResult, Encoding};

/// The encodings offered, as (label, name shown); the empty label is UTF-8.
pub const ENCODINGS: &[(&str, &str)] = &[
    ("", "UTF-8"),
    ("ISO-8859-1", "ISO-8859-1 (Latin-1)"),
    ("ISO-8859-2", "ISO-8859-2 (Central European)"),
    ("ISO-8859-5", "ISO-8859-5 (Cyrillic)"),
    ("ISO-8859-7", "ISO-8859-7 (Greek)"),
    ("ISO-8859-8", "ISO-8859-8 (Hebrew)"),
    ("ISO-8859-15", "ISO-8859-15 (Latin-9)"),
    ("windows-1250", "Windows-1250 (Central European)"),
    ("windows-1251", "Windows-1251 (Cyrillic)"),
    ("windows-1252", "Windows-1252 (Western)"),
    ("KOI8-R", "KOI8-R (Russian)"),
    ("KOI8-U", "KOI8-U (Ukrainian)"),
    ("IBM866", "CP866 (DOS Cyrillic)"),
    ("Shift_JIS", "Shift_JIS (Japanese)"),
    ("EUC-JP", "EUC-JP (Japanese)"),
    ("ISO-2022-JP", "ISO-2022-JP (Japanese)"),
    ("EUC-KR", "EUC-KR (Korean)"),
    ("GBK", "GBK (Simplified Chinese)"),
    ("GB18030", "GB18030 (Chinese)"),
    ("Big5", "Big5 (Traditional Chinese)"),
];

/// Index of `label` in `ENCODINGS` (0, UTF-8, when unknown).
pub fn index(label: &str) -> usize {
    ENCODINGS.iter().position(|(l, _)| l.eq_ignore_ascii_case(label)).unwrap_or(0)
}

/// The `ENCODINGS` label for an encoding name from elsewhere (e.g. SecureCRT), if offered.
pub fn label_for(name: &str) -> Option<&'static str> {
    let wanted = Encoding::for_label(name.trim().as_bytes())?;
    ENCODINGS.iter().map(|(l, _)| *l).find(|l| !l.is_empty() && Encoding::for_label(l.as_bytes()) == Some(wanted) && (l.eq_ignore_ascii_case(name.trim()) || *l != "ISO-8859-1"))
}

/// Converts one session's traffic; keeps state for characters split across reads.
pub struct Codec {
    /// ISO-8859-1 proper: every byte is the code point of the same value
    /// (the web's "latin1" label means Windows-1252 instead).
    latin1: bool,
    encoding: &'static Encoding,
    decoder: Decoder,
}

impl Codec {
    /// None for UTF-8, which needs no conversion.
    pub fn new(label: &str) -> Option<Codec> {
        let latin1 = label.eq_ignore_ascii_case("ISO-8859-1");
        let encoding = Encoding::for_label(label.as_bytes()).filter(|e| *e != encoding_rs::UTF_8)?;
        Some(Codec { latin1, encoding, decoder: encoding.new_decoder_without_bom_handling() })
    }

    /// Host bytes to UTF-8.
    pub fn decode(&mut self, bytes: &[u8]) -> Vec<u8> {
        if self.latin1 {
            return bytes.iter().map(|b| *b as char).collect::<String>().into_bytes();
        }
        let mut out = String::with_capacity(self.decoder.max_utf8_buffer_length(bytes.len()).unwrap_or(bytes.len() * 3));
        let mut input = bytes;
        loop {
            let (result, read, _) = self.decoder.decode_to_string(input, &mut out, false);
            input = &input[read..];
            match result {
                CoderResult::InputEmpty => break,
                CoderResult::OutputFull => out.reserve(input.len() * 3 + 16),
            }
        }
        out.into_bytes()
    }

    /// Typed UTF-8 to host bytes; characters the encoding lacks become '?'.
    pub fn encode(&self, utf8: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(utf8);
        if self.latin1 {
            return text.chars().map(|c| u8::try_from(c as u32).unwrap_or(b'?')).collect();
        }
        let mut encoder = self.encoding.new_encoder();
        let mut out = Vec::with_capacity(text.len() * 2 + 8);
        let mut buf = vec![0u8; text.len() * 4 + 16];
        let mut input = text.as_ref();
        loop {
            let (result, read, written) = encoder.encode_from_utf8_without_replacement(input, &mut buf, true);
            out.extend_from_slice(&buf[..written]);
            input = &input[read..];
            match result {
                EncoderResult::InputEmpty => break,
                EncoderResult::Unmappable(_) => out.push(b'?'),
                EncoderResult::OutputFull => buf.resize(buf.len() * 2, 0),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_both_ways_and_across_reads() {
        assert!(Codec::new("").is_none() && Codec::new("UTF-8").is_none());
        let mut latin1 = Codec::new("ISO-8859-1").unwrap();
        assert_eq!(latin1.decode(&[0x63, 0x61, 0x66, 0xe9, 0x80]), "café\u{80}".as_bytes());
        assert_eq!(latin1.encode("café€".as_bytes()), [0x63, 0x61, 0x66, 0xe9, b'?']);

        // Shift_JIS "日本" split in the middle of a character.
        let mut sjis = Codec::new("Shift_JIS").unwrap();
        let bytes = [0x93, 0xfa, 0x96, 0x7b];
        let mut text = sjis.decode(&bytes[..1]);
        text.extend(sjis.decode(&bytes[1..]));
        assert_eq!(String::from_utf8(text).unwrap(), "日本");
        assert_eq!(sjis.encode("日本".as_bytes()), bytes);

        let koi8 = Codec::new("KOI8-R").unwrap();
        assert_eq!(koi8.encode("Ж✓".as_bytes()), [0xf6, b'?']);
        assert_eq!((index("shift_jis"), index("nonsense")), (13, 0));
        assert_eq!((label_for("Big5"), label_for("ISO-8859-1"), label_for("Default")), (Some("Big5"), Some("ISO-8859-1"), None));
    }
}
