pub struct Config {
    pub name: String,
    pub value: i32,
}

impl Config {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            value: 0,
        }
    }
}
