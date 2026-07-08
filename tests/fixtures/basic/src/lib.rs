#![deny(warnings)]

/// A public struct without #[non_exhaustive].
pub struct Config {
    pub name: String,
    pub value: i32,
}

/// Public enum without #[non_exhaustive].
pub enum Status {
    Ok,
    Err,
}

/// Function with borrowed owned types.
pub fn process(data: &Vec<String>) -> &String {
    data.first().unwrap()
}

/// Another borrowed owned type.
pub fn handle(path: &PathBuf) -> &Path {
    path.as_path()
}

impl Config {
    pub fn new(name: String, value: i32) -> Self {
        Self { name, value }
    }
}
