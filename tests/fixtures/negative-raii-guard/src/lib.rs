// Negative fixture for pattern.raii-guard
// pub struct with <=8 fields should NOT trigger compose-structs
// and no explicit cleanup methods should trigger raii-guard

pub struct SafeHandle {
    pub fd: i32,
    pub owner: String,
    pub created_at: u64,
}

impl SafeHandle {
    pub fn new(fd: i32, owner: String) -> Self {
        Self {
            fd,
            owner,
            created_at: 0,
        }
    }

    // This is a regular method, not a cleanup method
    pub fn read(&self, buf: &mut [u8]) -> usize {
        buf.len()
    }
}
