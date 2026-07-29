// Positive fixture for anti.clone-to-satisfy-borrow-checker
// This should trigger findings: .clone() on owned types in public functions

pub fn process_data(data: String) -> String {
    // This is a borrow-checker workaround pattern
    let cloned = data.clone();
    format!("processed: {}", cloned)
}

pub fn get_items(items: Vec<String>) -> usize {
    let copy = items.clone();
    copy.len()
}
