use std::ops::Deref;

/// A domain struct — Deref to another domain struct is suspicious.
pub struct Wrapper {
    inner: String,
}

impl Deref for Wrapper {
    type Target = String;

    fn deref(&self) -> &String {
        &self.inner
    }
}
