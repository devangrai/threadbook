pub fn face_free_garment_crop_png() -> Vec<u8> {
    rgba_png(64, 64, |x, y| {
        let body = (18..=45).contains(&x) && (18..=55).contains(&y);
        let left_sleeve = (8..18).contains(&x) && (18..=34).contains(&y);
        let right_sleeve = (46..56).contains(&x) && (18..=34).contains(&y);
        let collar = (27..=36).contains(&x) && (18..=24).contains(&y);
        if (body || left_sleeve || right_sleeve) && !collar {
            [38, 122, 95, 255]
        } else {
            [245, 245, 242, 255]
        }
    })
}

pub fn solid_png(width: u32, height: u32) -> Vec<u8> {
    rgba_png(width, height, |_, _| [38, 122, 95, 255])
}

fn rgba_png(width: u32, height: u32, pixel: impl Fn(u32, u32) -> [u8; 4]) -> Vec<u8> {
    let row_bytes = usize::try_from(width)
        .expect("synthetic width fits usize")
        .checked_mul(4)
        .expect("synthetic row size does not overflow");
    let mut raw = Vec::with_capacity(
        (row_bytes + 1)
            .checked_mul(usize::try_from(height).expect("synthetic height fits usize"))
            .expect("synthetic image size does not overflow"),
    );
    for y in 0..height {
        raw.push(0);
        for x in 0..width {
            raw.extend_from_slice(&pixel(x, y));
        }
    }

    let compressed = zlib_stored(&raw);
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    append_chunk(&mut png, b"IHDR", &ihdr);
    append_chunk(&mut png, b"IDAT", &compressed);
    append_chunk(&mut png, b"IEND", &[]);
    png
}

fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![0x78, 0x01];
    if bytes.is_empty() {
        output.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    } else {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let length = remaining.len().min(u16::MAX as usize);
            let final_block = length == remaining.len();
            output.push(u8::from(final_block));
            let length_u16 = length as u16;
            output.extend_from_slice(&length_u16.to_le_bytes());
            output.extend_from_slice(&(!length_u16).to_le_bytes());
            output.extend_from_slice(&remaining[..length]);
            remaining = &remaining[length..];
        }
    }
    output.extend_from_slice(&adler32(bytes).to_be_bytes());
    output
}

fn append_chunk(output: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(data);
    let mut checksum_input = Vec::with_capacity(4 + data.len());
    checksum_input.extend_from_slice(kind);
    checksum_input.extend_from_slice(data);
    output.extend_from_slice(&crc32(&checksum_input).to_be_bytes());
}

fn adler32(bytes: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in bytes {
        a = (a + u32::from(*byte)) % MODULUS;
        b = (b + a) % MODULUS;
    }
    (b << 16) | a
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
