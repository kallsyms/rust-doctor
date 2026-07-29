// Positive fixture for pattern.raii-guard
// pub methods named close/free/release/dispose/shutdown that take &mut self should trigger

pub struct Connection {
    handle: i32,
}

impl Connection {
    pub fn new() -> Self {
        Self { handle: 42 }
    }

    pub fn close(&mut self) {
        self.handle = 0;
    }

    pub fn release(&mut self) {
        self.handle = -1;
    }
}
