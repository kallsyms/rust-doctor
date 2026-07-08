use std::ops::Deref;
use std::rc::Rc;

/// Smart pointer wrapper — Deref should be allowlisted.
pub struct MyBox<T: ?Sized>(Rc<T>);

impl<T: ?Sized> Deref for MyBox<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

/// String wrapper — Deref to str is allowlisted.
pub struct MyString(Rc<String>);

impl Deref for MyString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

/// Vec wrapper — Deref to [T] is allowlisted.
pub struct MyVec<T>(Rc<Vec<T>>);

impl<T> Deref for MyVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}
