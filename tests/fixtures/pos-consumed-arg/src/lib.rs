// Positive fixture for idiom.return-consumed-arg-on-error
// This should trigger findings: Result return with owned args

use std::io;

pub fn process_file(path: String) -> Result<String, io::Error> {
    // Consumed argument `path` but error type doesn't include it
    Ok(format!("processed: {}", path))
}
