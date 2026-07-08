//! Re-export all rule structs for the registry.

pub use super::anti_patterns::{AntiDenyWarnings, AntiDerefPolymorphism};
pub use super::idiom::{
    IdiomBorrowedArgs, IdiomDefaultTrait, IdiomOptionIteration, IdiomPrivacyExtensibility,
};
pub use super::patterns::{
    AntiCloneToSatisfyBorrowChecker, FfiIdiomaticErrors, PatternBuilder, PatternContainUnSafety,
    PatternCustomTraitsForBounds, PatternNewtype, PatternSmallCrates,
};
