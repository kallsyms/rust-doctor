/// Function with borrowed owned types.
pub fn process(data: &Vec<String>) -> &String {
    data.first().unwrap()
}

pub fn handle(path: &PathBuf) -> &Path {
    path.as_path()
}
