use crate::alloc::string::ToString;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use serenelib::debug_writer::{_print};
use serenelib::{println, print};

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum TarTypeFlag {
    Regular = b'0',
    Directory = b'5',
}

#[repr(C)]
pub struct TarHeader {
    name: [u8; 100],
    mode: [u8; 8],
    uid: [u8; 8],
    gid: [u8; 8],
    size: [u8; 12],
    mtime: [u8; 12],
    chksum: [u8; 8],
    typeflag: TarTypeFlag,
    linkname: [u8; 100],
    magic: [u8; 6],
    version: [u8; 2],
    uname: [u8; 32],
    gname: [u8; 32],
    devmajor: [u8; 8],
    devminor: [u8; 8],
    prefix: [u8; 155],
    reserved: [u8; 12],
}

impl TarHeader {
    pub fn get_size(&self) -> usize {
        let size_str = core::str::from_utf8(&self.size)
            .unwrap_or("")
            .trim_end_matches('\0')
            .trim();
        println!("size_str: '{}'", size_str);
        usize::from_str_radix(size_str, 8).unwrap()
    }
}

pub struct TarHeaderIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for TarHeaderIterator<'a> {
    type Item = &'a TarHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }
        let header = unsafe {
            &*(self.data[self.offset..self.offset + core::mem::size_of::<TarHeader>()].as_ptr() as *const TarHeader)
        };
        if header.name[0] == b'\0' {
            return None;
        }
        let size = header.get_size();
        let file_size = ((size + 511) / 512) * 512;
        self.offset += 512 + file_size;
        Some(header)
    }
}

pub struct TarArchive<'a> {
    data: &'a [u8],
}

impl TarArchive<'_> {
    pub fn new(data: &[u8]) -> TarArchive<'_> {
        TarArchive { data }
    }

    pub fn iter_headers(&self) -> TarHeaderIterator<'_> {
        TarHeaderIterator {
            data: self.data,
            offset: 0,
        }
    }

    pub fn list(&self, path: &str) -> Vec<String> {
        let mut files = Vec::new();
        for header in self.iter_headers() {
            let name = core::str::from_utf8(&header.name)
                .unwrap_or("")
                .trim_end_matches('\0');
            let full_path = if name.starts_with("./") {
                format!("/{}", &name[2..])
            } else {
                name.to_string()
            };
            if full_path.starts_with(path) {
                files.push(full_path);
            }
        }
        files
    }
    

    pub fn read(&self, path: &str) -> Option<&[u8]> {
        let mut offset = 0;
        for header in self.iter_headers() {
            let name = core::str::from_utf8(&header.name)
                .unwrap_or("")
                .trim_end_matches('\0');
            let full_path = if name.starts_with("./") {
                format!("/{}", &name[2..])
            } else {
                name.to_string()
            };

            let size = header.get_size();
            let file_size = ((size + 511) / 512) * 512;
            offset += 512;
            if full_path == path {
                if size == 0 {
                    return Some(&[]);
                }
                if header.typeflag == TarTypeFlag::Directory {
                    return None;
                }
                return Some(&self.data[offset..offset + size]);
            }
            offset += file_size;
        }
        None
    }
}