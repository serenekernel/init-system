use serenelib::syscalls::{
    sys_process_create_empty, sys_memobj_create, sys_map, sys_copy_to, sys_start,
    MemObjPerms, MemObjMapFlags, SyscallError,
};
use serenelib::ipc::Handle;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

pub const PT_LOAD: u32 = 1;

pub const PF_X: u32 = 1 << 0;
pub const PF_W: u32 = 1 << 1;
pub const PF_R: u32 = 1 << 2;

const PAGE_SIZE: usize = 4096;

fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)

}

fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}



pub fn load_elf(elf_data: &[u8]) -> Result<(Handle, usize), SyscallError> {
    if elf_data.len() < core::mem::size_of::<Elf64Header>() {
        return Err(SyscallError::InvalidArgument);
    }
    
    let header = unsafe {
        &*(elf_data.as_ptr() as *const Elf64Header)
    };
    
    if &header.e_ident[0..4] != b"\x7fELF" {
        return Err(SyscallError::InvalidArgument);
    }
    
    if header.e_ident[4] != 2 {
        return Err(SyscallError::InvalidArgument);
    }
    
    let process = sys_process_create_empty()?;
    
    let phoff = header.e_phoff as usize;
    let phentsize = header.e_phentsize as usize;
    let phnum = header.e_phnum as usize;
    
    for i in 0..phnum {
        let ph_offset = phoff + i * phentsize;
        if ph_offset + core::mem::size_of::<Elf64ProgramHeader>() > elf_data.len() {
            return Err(SyscallError::InvalidArgument);
        }
        
        let ph = unsafe {
            &*(elf_data.as_ptr().add(ph_offset) as *const Elf64ProgramHeader)
        };
        
        if ph.p_type != PT_LOAD {
            continue;
        }
        
        let vaddr_start = align_down(ph.p_vaddr as usize, PAGE_SIZE);
        let vaddr_end = align_up((ph.p_vaddr + ph.p_memsz) as usize, PAGE_SIZE);
        let segment_size = vaddr_end - vaddr_start;

        let mut perms = MemObjPerms::empty();
        if ph.p_flags & PF_R != 0 {
            perms |= MemObjPerms::READ;
        }
        if ph.p_flags & PF_W != 0 {
            perms |= MemObjPerms::WRITE;
        }
        if ph.p_flags & PF_X != 0 {
            perms |= MemObjPerms::EXEC;
        }
        
        let memobj = sys_memobj_create(segment_size, perms)?;
        
        let mapped_vaddr = sys_map(
            process,
            memobj,
            Some(vaddr_start as u64),
            perms,
            MemObjMapFlags::FIXED,
        )?;
        
        if mapped_vaddr != vaddr_start {
            return Err(SyscallError::AddressInUse);
        }
        
        let file_offset = ph.p_offset as usize;
        let file_size = ph.p_filesz as usize;
        
        if file_size > 0 {
            if file_offset + file_size > elf_data.len() {
                return Err(SyscallError::InvalidArgument);
            }
            
            let src_data = &elf_data[file_offset..file_offset + file_size];
            let dst_addr = ph.p_vaddr as usize;
            
            sys_copy_to(
                process,
                dst_addr,
                src_data.as_ptr(),
                file_size,
            )?;
        }
    }
    
    Ok((process, header.e_entry as usize))
}