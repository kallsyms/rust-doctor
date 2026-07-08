/// A public struct with #[non_exhaustive].
#[non_exhaustive]
pub struct Config {
    pub name: String,
    pub value: i32,
}

/// Function with proper borrowed types.
pub fn process(data: &str) -> &str {
    data
}

pub fn handle(path: &std::path::Path) -> &std::path::Path {
    path
}

impl Config {
    pub fn new(name: String, value: i32) -> Self {
        Self { name, value }
    }
}
