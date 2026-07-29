//! Re-export all rule structs for the registry.

pub use super::anti_patterns::{AntiDenyWarnings, AntiDerefPolymorphism};
pub use super::idiom::{
    IdiomBorrowedArgs, IdiomDefaultTrait, IdiomMemTakeReplace, IdiomOptionIteration,
    IdiomPrivacyExtensibility, IdiomReturnConsumedArgOnError, IdiomTemporaryMutability,
};
pub use super::patterns::{
    AntiCloneToSatisfyBorrowChecker, FfiIdiomaticErrors, PatternBuilder, PatternComposeStructs,
    PatternContainUnSafety, PatternCustomTraitsForBounds, PatternNewtype, PatternRaiiGuard,
    PatternSmallCrates,
};
