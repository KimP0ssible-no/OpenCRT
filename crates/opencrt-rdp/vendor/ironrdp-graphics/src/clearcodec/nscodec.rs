//! NSCodec ([MS-RDPNSC]) as a ClearCodec subcodec: four planes (luma, orange
//! and green chroma, alpha), each raw or run-length encoded, with colour loss
//! and optional 2x2 chroma subsampling, in the YCoCg colour space.
//!
//! [MS-RDPNSC]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpnsc/

/// Decodes `width` x `height` pixels to BGRA rows, or None if the stream is
/// malformed.
pub(crate) fn decode(data: &[u8], width: usize, height: usize) -> Option<Vec<u8>> {
    let header = data.get(..20)?;
    let count = |i: usize| usize::try_from(u32::from_le_bytes(header[i * 4..i * 4 + 4].try_into().ok()?)).ok();
    let counts = [count(0)?, count(1)?, count(2)?, count(3)?];
    let color_loss = header[16];
    let subsampled = header[17] != 0;
    if !(1..=7).contains(&color_loss) {
        return None;
    }

    // Plane sizes once decoded: with subsampling, luma rows are padded to a
    // multiple of 8 and chroma is a quarter of that (height padded to 2).
    let padded_width = width.div_ceil(8) * 8;
    let sizes = if subsampled {
        let chroma = (padded_width / 2) * height.div_ceil(2);
        [padded_width * height, chroma, chroma, width * height]
    } else {
        [width * height; 4]
    };

    let mut planes: [Vec<u8>; 4] = Default::default();
    let mut rest = &data[20..];
    for i in 0..4 {
        let encoded = rest.get(..counts[i])?;
        rest = &rest[counts[i]..];
        planes[i] = if counts[i] == 0 {
            vec![0xFF; sizes[i]] // no plane: opaque (alpha) / full
        } else if counts[i] < sizes[i] {
            rle(encoded, sizes[i])?
        } else {
            encoded[..sizes[i]].to_vec()
        };
    }

    let shift = color_loss - 1;
    let chroma = |v: u8| i32::from((v << shift) as i8);
    let mut out = Vec::with_capacity(width * height * 4);
    for y in 0..height {
        let (luma_row, chroma_row, step) = if subsampled { (y * padded_width, (y / 2) * (padded_width / 2), 2) } else { (y * width, y * width, 1) };
        for x in 0..width {
            let luma = i32::from(planes[0][luma_row + x]);
            let c = chroma_row + x / step;
            let (co, cg) = (chroma(planes[1][c]), chroma(planes[2][c]));
            let clamp = |v: i32| v.clamp(0, 255) as u8;
            out.extend([clamp(luma - co - cg), clamp(luma + cg), clamp(luma + co - cg), planes[3][y * width + x]]);
        }
    }
    Some(out)
}

/// NSCodec RLE: a byte, or a byte repeated (twice in the stream) followed by
/// a run length (that + 2, or after 0xFF a u32 that is the length itself);
/// the last four bytes of the plane come raw at the end.
fn rle(data: &[u8], size: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(size);
    let mut i = 0;
    while size - out.len() > 4 {
        let value = *data.get(i)?;
        i += 1;
        if size - out.len() == 5 || data.get(i) != Some(&value) {
            out.push(value);
            continue;
        }
        i += 1;
        let factor = *data.get(i)?;
        i += 1;
        let run = if factor < 0xFF {
            usize::from(factor) + 2
        } else {
            let long = u32::from_le_bytes(data.get(i..i + 4)?.try_into().ok()?);
            i += 4;
            usize::try_from(long).ok()?
        };
        out.resize((out.len() + run).min(size - 4), value);
    }
    out.extend_from_slice(data.get(i..i + 4)?);
    Some(out)
}
