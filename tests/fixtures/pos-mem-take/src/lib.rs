// Positive fixture for idiom.mem-take-replace
// This should trigger findings: .clone() followed by .clear() pattern

pub fn drain_buffer(buf: &mut Vec<String>) -> Vec<String> {
    let data = buf.clone();
    buf.clear();
    data
}
