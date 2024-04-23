#![no_std]

#[derive(Debug)]
pub struct SyscallReadLogging {
    pub buffer_addr: u64,
    pub calling_size: u64,
}

impl Default for SyscallReadLogging {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallReadLogging {
    #[inline(always)]
    pub fn new() -> SyscallReadLogging {
        SyscallReadLogging {
            buffer_addr: u64::default(),
            calling_size: u64::default(),
        }
    }
}

#[derive(Debug)]
pub struct StringInfo {
    pub str: [u8; 740],
}

impl Default for StringInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl StringInfo {
    #[inline(always)]
    pub fn new() -> StringInfo {
        StringInfo { str: [0; 740] }
    }
}
