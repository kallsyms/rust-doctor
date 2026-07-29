// Negative fixture for anti.clone-to-satisfy-borrow-checker
// No .clone() on owned types in public functions

pub fn process_data(data: &str) -> String {
    format!("processed: {}", data)
}

pub fn get_items(items: &[String]) -> usize {
    items.len()
}
