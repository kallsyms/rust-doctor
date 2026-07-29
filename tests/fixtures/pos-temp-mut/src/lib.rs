// Positive fixture for idiom.temporary-mutability
// This should trigger findings: `let mut` with no reassignment

pub fn build_string() -> String {
    let mut result = String::new();
    result.push_str("hello");
    result
}

pub fn build_path() -> String {
    let mut path = String::from("/tmp");
    path
}
