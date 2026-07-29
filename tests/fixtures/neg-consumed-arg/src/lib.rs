// Negative fixture for idiom.return-consumed-arg-on-error
// No Result return with owned args

pub fn process_file(path: &str) -> Result<String, std::io::Error> {
    Ok(format!("processed: {}", path))
}
