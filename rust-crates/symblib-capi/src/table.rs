use crate::{rangeextr_impl, FfiResult, StatusCode};
use std::collections::HashMap;
use std::ffi::c_int;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::fd::FromRawFd;

const MAGIC: u32 = 0x6c627467; // "gtbl"
const VERSION: u32 = 1;

#[repr(C)]
struct Header {
    magic: u32,
    version: u32,
    ranges_offset: u64,
    strings_offset: u64,
}

#[no_mangle]
pub unsafe extern "C" fn symblib_exe_fd_to_table(
    executable_fd: c_int,
    dwarf_sup_fd: c_int,
    output_fd: c_int,
) -> StatusCode {
    let executable = File::from_raw_fd(executable_fd);
    let dwarf_sup = match dwarf_sup_fd {
        -1 => None,
        dwarf_sup_fd => Some(File::from_raw_fd(dwarf_sup_fd)),
    };
    let mut out = File::from_raw_fd(output_fd);

    let res = symblib_exe_to_table_impl(&executable, &dwarf_sup, &mut out);

    std::mem::forget(executable);
    std::mem::forget(out);
    std::mem::forget(dwarf_sup);

    res.into()
}

struct StringBuilder {
    buf: Vec<u8>,
    unique: HashMap<String, u32>,
    offset: u64,
}

impl StringBuilder {
    fn new() -> StringBuilder {
        StringBuilder {
            buf: Vec::new(),
            unique: HashMap::new(),
            offset: 0,
        }
    }

    fn add(&mut self, s: &str) -> FfiResult<u32> {
        match self.unique.get(s) {
            Some(id) => Ok(*id),
            None => {
                let o = self.offset;
                if o >= u32::MAX as u64 {
                    return Err(StatusCode::U32Overflow);
                }
                let bs = s.as_bytes();
                let len = bs.len();
                if len >= u32::MAX as usize {
                    return Err(StatusCode::U32Overflow);
                }
                let len = len as u32;
                self.buf.extend_from_slice(&len.to_le_bytes());
                self.buf.extend_from_slice(bs);
                self.offset += len as u64 + 4;
                self.unique.insert(s.to_string(), o as u32);
                Ok(o as u32)
            }
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[repr(C)]
struct RangeEntry {
    va: u32,
    len: u32,
    depth: u32,
    func: u32,
}

struct RangesBuilder {
    entries: Vec<RangeEntry>,
}

impl RangesBuilder {
    fn new() -> RangesBuilder {
        RangesBuilder {
            entries: Vec::new(),
        }
    }

    fn add(&mut self, va: u32, len: u32, depth: u32, func: u32) {
        let entry = RangeEntry {
            va,
            len,
            depth,
            func,
        };
        self.entries.push(entry);
    }

    fn finish(&mut self) -> Vec<RangeEntry> {
        self.entries.sort_by(|a, b| match a.va.cmp(&b.va) {
            std::cmp::Ordering::Equal => a.depth.cmp(&b.depth),
            other => other,
        });
        std::mem::take(&mut self.entries)
    }
}

fn symblib_exe_to_table_impl(
    executable: &File,
    dwarf_sup: &Option<File>,
    output: &mut File,
) -> FfiResult<()> {
    let mut str = StringBuilder::new();
    let mut rngb = RangesBuilder::new();

    rangeextr_impl(executable, dwarf_sup, &mut |rng| {
        let func = str.add(&rng.func)?;
        if rng.elf_va >= u32::MAX as u64 {
            return Err(Box::new(StatusCode::U32Overflow));
        }
        let va = rng.elf_va as u64 as u32;
        rngb.add(va, rng.length, rng.depth, func);
        Ok(())
    })?;

    let ranges = rngb.finish();
    let string_bytes = str.into_bytes();

    concat_symb_file(output, &ranges, &string_bytes)?;

    Ok(())
}

fn concat_symb_file(
    output_file: &mut File,
    ranges: &[RangeEntry],
    strings: &[u8],
) -> Result<(), StatusCode> {
    let header = Header {
        magic: MAGIC,
        version: VERSION,
        ranges_offset: 0,
        strings_offset: 0,
    };
    let header_bytes = unsafe {
        std::slice::from_raw_parts(&header as *const Header as *const u8, size_of::<Header>())
    };
    output_file.write_all(header_bytes)?;

    let current_pos = output_file.seek(SeekFrom::Current(0))?;
    let padding = (16 - (current_pos % 16)) % 16;
    if padding > 0 {
        output_file.write_all(&vec![0u8; padding as usize])?;
    }

    let ranges_offset = output_file.seek(SeekFrom::Current(0))?;

    let ranges_bytes = unsafe {
        std::slice::from_raw_parts(
            ranges.as_ptr() as *const u8,
            ranges.len() * size_of::<RangeEntry>(),
        )
    };
    output_file.write_all(ranges_bytes)?;

    let current_pos = output_file.seek(SeekFrom::Current(0))?;
    let padding = (16 - (current_pos % 16)) % 16;
    if padding > 0 {
        output_file.write_all(&vec![0u8; padding as usize])?;
    }

    let strings_offset = output_file.seek(SeekFrom::Current(0))?;
    output_file.write_all(strings)?;

    output_file.seek(SeekFrom::Start(0))?;
    let header = Header {
        magic: MAGIC,
        version: VERSION,
        ranges_offset,
        strings_offset,
    };
    let header_bytes = unsafe {
        std::slice::from_raw_parts(&header as *const Header as *const u8, size_of::<Header>())
    };
    output_file.write_all(header_bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_string_builder_file_layout() -> FfiResult<()> {
        let temp_file = NamedTempFile::new().unwrap();
        {
            let mut builder = StringBuilder::new();
            builder.add("hello")?;
            builder.add("world")?;
            let bytes = builder.into_bytes();
            temp_file.as_file().write_all(&bytes)?;
        }
        let mut file = OpenOptions::new().read(true).open(temp_file.path())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        let expected = vec![
            5, 0, 0, 0, b'h', b'e', b'l', b'l', b'o', 5, 0, 0, 0, b'w', b'o', b'r', b'l', b'd',
        ];

        assert_eq!(contents, expected);
        Ok(())
    }

    #[test]
    fn test_table() {
        let testdata = vec!["/proc/self/exe", "/lib/x86_64-linux-gnu/libc.so.6"];

        for exe_path in testdata {
            let mut f = NamedTempFile::new().unwrap();
            let exe = OpenOptions::new().read(true).open(exe_path).unwrap();
            let res = symblib_exe_to_table_impl(&exe, &None, f.as_file_mut());
            assert_eq!(res, Ok(()));
        }
    }

    #[test]
    fn test_ranges_builder() -> FfiResult<()> {
        let mut builder = RangesBuilder::new();
        builder.add(0x2000, 200, 1, 43);
        builder.add(0x1000, 100, 0, 42);
        let ranges = builder.finish();

        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].va, 0x1000);
        assert_eq!(ranges[0].len, 100);
        assert_eq!(ranges[0].depth, 0);
        assert_eq!(ranges[0].func, 42);
        assert_eq!(ranges[1].va, 0x2000);
        assert_eq!(ranges[1].len, 200);
        assert_eq!(ranges[1].depth, 1);
        assert_eq!(ranges[1].func, 43);
        Ok(())
    }

    #[test]
    fn test_symb_file_layout() -> FfiResult<()> {
        let mut temp_out = tempfile::Builder::new().tempfile().unwrap();

        let mut builder = StringBuilder::new();
        builder.add("func1")?; // offset 0
        builder.add("func2")?; // offset 9
        let str_bytes = builder.into_bytes();

        let mut builder = RangesBuilder::new();
        builder.add(0x1000, 100, 0, 0); // points to "func1"
        builder.add(0x2000, 200, 1, 9); // points to "func2"
        let ranges = builder.finish();

        concat_symb_file(temp_out.as_file_mut(), &ranges, &str_bytes)?;

        let mut file = OpenOptions::new().read(true).open(temp_out.path())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        let expected = vec![
            0x67, 0x74, 0x62, 0x6C, // magic: "gtbl"
            0x01, 0x00, 0x00, 0x00, // version: 1
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // ranges_offset: 32 (aligned to 16)
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // strings_offset: 64 (aligned to 16)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, // va: 0x1000
            0x64, 0x00, 0x00, 0x00, // len: 100
            0x00, 0x00, 0x00, 0x00, // depth: 0
            0x00, 0x00, 0x00, 0x00, // func_id: 0
            0x00, 0x20, 0x00, 0x00, // va: 0x2000
            0xC8, 0x00, 0x00, 0x00, // len: 200
            0x01, 0x00, 0x00, 0x00, // depth: 1
            0x09, 0x00, 0x00, 0x00, // func_id: 9
            0x05, 0x00, 0x00, 0x00, // len: 5
            b'f', b'u', b'n', b'c', b'1', // "func1"
            0x05, 0x00, 0x00, 0x00, // len: 5
            b'f', b'u', b'n', b'c', b'2', // "func2"
        ];

        assert_eq!(contents, expected);
        Ok(())
    }

    #[test]
    fn test_libc() -> FfiResult<()> {
        let libc = OpenOptions::new()
            .read(true)
            .open("/usr/lib/x86_64-linux-gnu/libc.so.6")?;

        let debug = OpenOptions::new()
            .read(true)
            .open("/usr/lib/debug/.build-id/6d/64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug")?;
        let mut out = NamedTempFile::new()?;
        symblib_exe_to_table_impl(&libc, &Some(debug), out.as_file_mut())?;
        return Ok(());
    }
}
