// Negative fixture for pattern.compose-structs
// pub struct with <=8 fields should NOT trigger the rule

pub struct SmallConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub timeout_ms: u64,
}

impl SmallConfig {
    pub fn new() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 8080,
            database: "main".to_string(),
            timeout_ms: 30_000,
        }
    }
}
