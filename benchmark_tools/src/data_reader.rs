use std::fs::File;
use std::hash::{BuildHasher, Hasher};
use std::io::{BufReader, BufRead, Error, Read};
use byteorder::{ReadBytesExt, LittleEndian};

pub fn test_hasher<B: BuildHasher>(input_file: File, builder: B) -> Result<u64, Error> {
    let mut result: u64 = 0;
    let mut input = BufReader::new(input_file);
    let mut hasher = builder.build_hasher();
    while input.has_data_left()? {
        let code = input.read_u8()?;
        match code {
            b'1' => {
                let i = input.read_u8()?;
                hasher.write_u8(i);
            }
            b'2' => {
                let i = input.read_u16::<LittleEndian>()?;
                hasher.write_u16(i);
            }
            b'4' => {
                let i = input.read_u32::<LittleEndian>()?;
                hasher.write_u32(i);
            }
            b'8' => {
                let i = input.read_u64::<LittleEndian>()?;
                hasher.write_u64(i);
            }
            b'B' => {
                let i = input.read_u128::<LittleEndian>()?;
                hasher.write_u128(i);
            }
            b'u' => {
                let i = input.read_u64::<LittleEndian>()?;
                hasher.write_usize(i as usize);
            }
            b's' => {
                let len = input.read_u32::<LittleEndian>()?;
                let mut slice = vec![0; len as usize];
                input.read_exact(&mut slice[..])?;
                hasher.write(&slice[..]);
            }
            b'f' => {
                result = result.wrapping_add(hasher.finish());
                hasher = builder.build_hasher();
            }
            code => panic!("Unexpected code: {}", code)
        }
    }
    Ok(result)
}