//! Base92 encoding/decoding, mirroring `upb/mini_descriptor/internal/base92.*`
//! and the varint scheme in `_upb_Base92_DecodeVarint`.

/// `_kUpb_ToBase92` (upb/mini_descriptor/internal/base92.c:10-18).
pub const TO_BASE92: &[u8; 92] =
    b" !#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~";

/// `_kUpb_FromBase92` (upb/mini_descriptor/internal/base92.c:20-26),
/// indexed by `ch - ' '` (ch in ' '..='~' gives indices 0..=94); -1 marks
/// characters outside the alphabet ('"' at index 2, '\'' at 7, '\\' at 60).
pub const FROM_BASE92: [i8; 95] = [
    0, 1, -1, 2, 3, 4, 5, -1, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
    71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91,
];

/// `_upb_ToBase92(ch)`.
pub fn to_base92(ch: i8) -> u8 {
    assert!((0..92).contains(&ch), "base92 value out of range: {ch}");
    TO_BASE92[ch as usize]
}

/// `_upb_FromBase92(ch)`; returns None for characters outside the alphabet.
pub fn from_base92(ch: u8) -> Option<i8> {
    if !(b' '..=b'~').contains(&ch) {
        return None;
    }
    let v = FROM_BASE92[(ch - b' ') as usize];
    if v < 0 {
        None
    } else {
        Some(v)
    }
}

/// The number of bits per character for a varint in `[min, max]`:
/// `upb_Log2Ceiling(from_base92(max) - from_base92(min))` — note there is no
/// `+1` on the range in the decoder (upb/base/internal/log2.h semantics:
/// ceiling of log2, with log2_ceiling(x) for x=0 being 0 and 2^k for
/// 2^(k-1) < x <= 2^k).
pub fn bits_per_char(min: u8, max: u8) -> u32 {
    let range = (from_base92(max).unwrap() - from_base92(min).unwrap()) as u32;
    log2_ceiling(range)
}

fn log2_ceiling(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    let mut v = x;
    let mut bits = 0;
    while v > 1 {
        v >>= 1;
        bits += 1;
    }
    // log2_ceiling(x): smallest k with 2^k >= x. For x a power of two the
    // bit length minus one is exactly log2; for others it is one short.
    if x.is_power_of_two() {
        bits
    } else {
        bits + 1
    }
}

/// `_upb_Base92_DecodeVarint`: decodes a varint whose first character is
/// `first_ch`, consuming subsequent characters from `data[i..]` while they
/// fall within `[min, max]`. Returns (value, index past the varint), or an
/// error for an overlong varint (shift >= 32).
pub fn decode_varint(
    data: &[u8],
    i: usize,
    first_ch: u8,
    min: u8,
    max: u8,
) -> Result<(u32, usize), DecodeError> {
    let bpc = bits_per_char(min, max);
    let mut val: u32 = 0;
    let mut shift: u32 = 0;
    let mut ch = first_ch;
    let mut idx = i;
    loop {
        let bits = (from_base92(ch).unwrap() - from_base92(min).unwrap()) as u32;
        val |= bits << shift;
        if idx == data.len() || data[idx] < min || max < data[idx] {
            return Ok((val, idx));
        }
        ch = data[idx];
        idx += 1;
        shift += bpc;
        if shift >= 32 {
            return Err(DecodeError::OverlongVarint);
        }
    }
}

/// `upb_MtDataEncoder_PutBase92Varint`: encodes `val` in the `[min, max]`
/// alphabet (generation tooling; the encoder uses `+1` on the range).
pub fn encode_varint(out: &mut Vec<u8>, mut val: u32, min: u8, max: u8) {
    let shift = bits_per_char_enc(min, max);
    let mask = (1u32 << shift) - 1;
    loop {
        let bits = val & mask;
        out.push(to_base92(bits as i8 + from_base92(min).unwrap()));
        val >>= shift;
        if val == 0 {
            break;
        }
    }
}

/// Encoder-side bits per char: `log2_ceiling(from_base92(max) -
/// from_base92(min) + 1)` (upb/mini_descriptor/internal/encode.c:68).
fn bits_per_char_enc(min: u8, max: u8) -> u32 {
    let range = (from_base92(max).unwrap() - from_base92(min).unwrap()) as u32 + 1;
    log2_ceiling(range)
}

/// A mini descriptor decode failure. The message mirrors the upstream error
/// string (upb_MdDecoder_ErrorJmp), which is stable at the pinned commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The upstream error message, including the "Error building mini table: "
    /// prefix used by upb_MdDecoder_ErrorJmp.
    Message(String),
    /// An overlong base92 varint ("Overlong varint").
    OverlongVarint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_roundtrip() {
        for (i, &ch) in TO_BASE92.iter().enumerate() {
            assert_eq!(from_base92(ch), Some(i as i8));
        }
    }

    #[test]
    fn invalid_chars_rejected() {
        assert_eq!(from_base92(b'"'), None);
        assert_eq!(from_base92(b'\''), None);
        assert_eq!(from_base92(b'\x7f'), None);
    }

    #[test]
    fn varint_roundtrip() {
        for &(min, max) in &[(b'L', b'['), (b'_', b'~'), (b' ', b'b')] {
            for &v in &[0u32, 1, 3, 7, 8, 15, 16, 31, 63, 255, 1024, u32::MAX] {
                let mut enc = Vec::new();
                encode_varint(&mut enc, v, min, max);
                let (dec, idx) = decode_varint(&enc, 1, enc[0], min, max).unwrap();
                assert_eq!(dec, v, "value {v} min {min} max {max}");
                assert_eq!(idx, enc.len());
            }
        }
    }
}
