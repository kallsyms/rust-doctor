pub fn do_stuff() {
    let opt = Some(42);
    if let Some(x) = opt {
        println!("{x}");
    }
}
