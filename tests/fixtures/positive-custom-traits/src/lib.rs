/// Public trait with complex bounds — should trigger.
pub trait ComplexTrait: Clone + Send + Sync + 'static
where
    Self: std::fmt::Debug + std::fmt::Display + std::hash::Hash + Eq + Ord,
{
    fn compute(&self) -> i32;
}
