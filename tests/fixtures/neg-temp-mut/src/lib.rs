// Negative fixture for idiom.temporary-mutability
// No unnecessary `mut` declarations

pub fn build_string() -> String {
    let result = String::new();
    result
}

pub fn build_path() -> String {
    let path = String::from("/tmp");
    path
}
