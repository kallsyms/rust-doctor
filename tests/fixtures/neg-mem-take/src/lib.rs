// Negative fixture for idiom.mem-take-replace
// No clone+clear pattern

pub fn drain_buffer(buf: &mut Vec<String>) -> Vec<String> {
    std::mem::take(buf)
}
