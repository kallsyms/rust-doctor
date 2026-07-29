// Positive fixture for pattern.compose-structs
// pub struct with >8 fields should trigger the rule

pub struct BigConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
    pub timeout_ms: u64,
    pub max_connections: u32,
    pub retry_count: u32,
    pub use_ssl: bool,
    pub log_level: String,
}

impl BigConfig {
    pub fn new() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 8080,
            username: "admin".to_string(),
            password: "".to_string(),
            database: "main".to_string(),
            timeout_ms: 30_000,
            max_connections: 10,
            retry_count: 3,
            use_ssl: false,
            log_level: "info".to_string(),
        }
    }
}
