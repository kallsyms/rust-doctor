//! Rule trait, RuleContext, and rule registry.
//!
//! Rules are stateless checkers that operate on [`RuleContext`] and emit
//! [`Finding`](crate::diagnostic::Finding)s.  The registry holds the
//! concrete rule instances and drives execution.

use crate::diagnostic::Finding;
use cargo_metadata::{Metadata, Package, PackageId};
use std::path::{Path, PathBuf};

pub struct PackageManifest {
    pub package_name: String,
    pub path: PathBuf,
    pub content: String,
}

// ---------------------------------------------------------------------------
// RuleContext
// ---------------------------------------------------------------------------

/// Shared context passed to every rule during a scan.
pub struct RuleContext<'a> {
    /// Root of the workspace (may differ from the scanned directory).
    pub workspace_root: PathBuf,
    /// Metadata from `cargo metadata`.
    pub metadata: &'a Metadata,
    pub manifests: Vec<PackageManifest>,
    pub package_source_files: std::collections::HashMap<PackageId, Vec<PathBuf>>,
}

impl RuleContext<'_> {
    pub fn source_files(&self, package: &Package) -> impl Iterator<Item = &Path> {
        self.package_source_files
            .get(&package.id)
            .into_iter()
            .flatten()
            .map(PathBuf::as_path)
    }
}

// ---------------------------------------------------------------------------
// Rule trait
// ---------------------------------------------------------------------------

/// A single diagnostic rule.
///
/// Implementations inspect the AST / metadata supplied by [`RuleContext`]
/// and push findings into `out`.
pub trait Rule: Send + Sync {
    /// Stable, machine-readable identifier (e.g. `"anti.deny-warnings"`).
    fn id(&self) -> &'static str;

    /// Human-friendly title shown in output.
    fn title(&self) -> &'static str;

    /// High-level classification of this rule.
    fn category(&self) -> crate::diagnostic::Category;

    /// Default severity when the rule fires.
    fn default_severity(&self) -> crate::diagnostic::Severity;

    /// Default confidence level.
    fn default_confidence(&self) -> crate::diagnostic::Confidence;

    /// Run this rule against the workspace and emit findings.
    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()>;

    /// One-line description of what the rule looks for.
    fn description(&self) -> &'static str {
        ""
    }

    /// Links to external documentation / references.
    fn references(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// A prompt an LLM agent can use to fix the issue.
    fn llm_fix_prompt(&self) -> Option<&'static str> {
        None
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Holds all registered rule instances and provides iteration helpers.
pub struct Registry {
    rules: Vec<Box<dyn Rule>>,
}

impl Registry {
    pub fn new() -> Self {
        let mut reg = Self { rules: Vec::new() };
        reg.register_builtin();
        reg
    }

    /// Register a rule instance.
    pub fn register(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    /// Register all built-in MVP + stub rules.
    fn register_builtin(&mut self) {
        use crate::rules::rules::*;
        self.register(Box::new(AntiDenyWarnings));
        self.register(Box::new(AntiDerefPolymorphism));
        self.register(Box::new(AntiCloneToSatisfyBorrowChecker));
        self.register(Box::new(IdiomBorrowedArgs));
        self.register(Box::new(IdiomDefaultTrait));
        self.register(Box::new(IdiomOptionIteration));
        self.register(Box::new(IdiomPrivacyExtensibility));
        self.register(Box::new(IdiomTemporaryMutability));
        self.register(Box::new(IdiomReturnConsumedArgOnError));
        self.register(Box::new(IdiomMemTakeReplace));
        self.register(Box::new(PatternBuilder));
        self.register(Box::new(PatternContainUnSafety));
        self.register(Box::new(PatternCustomTraitsForBounds));
        self.register(Box::new(PatternSmallCrates));
        self.register(Box::new(PatternComposeStructs));
        self.register(Box::new(PatternRaiiGuard));
        // Phase-3 stubs (inert):
        self.register(Box::new(FfiIdiomaticErrors));
        self.register(Box::new(PatternNewtype));
    }

    /// Iterate over all rules.
    pub fn iter(&self) -> impl Iterator<Item = &dyn Rule> {
        self.rules.iter().map(|r| r.as_ref())
    }

    /// Return the rule with the given ID, if any.
    pub fn get(&self, id: &str) -> Option<&dyn Rule> {
        self.rules.iter().find(|r| r.id() == id).map(|r| r.as_ref())
    }

    /// Return IDs of all registered rules.
    pub fn rule_ids(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.id()).collect()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_expected_rules() {
        let reg = Registry::new();
        let ids = reg.rule_ids();
        assert!(ids.contains(&"anti.deny-warnings"));
        assert!(ids.contains(&"anti.deref-polymorphism"));
        assert!(ids.contains(&"anti.clone-to-satisfy-borrow-checker"));
        assert!(ids.contains(&"idiom.borrowed-args"));
        assert!(ids.contains(&"idiom.default-trait"));
        assert!(ids.contains(&"idiom.option-iteration"));
        assert!(ids.contains(&"idiom.privacy-extensibility"));
        assert!(ids.contains(&"idiom.temporary-mutability"));
        assert!(ids.contains(&"idiom.return-consumed-arg-on-error"));
        assert!(ids.contains(&"idiom.mem-take-replace"));
        assert!(ids.contains(&"pattern.builder"));
        assert!(ids.contains(&"pattern.contain-unsafety"));
        assert!(ids.contains(&"pattern.custom-traits-for-bounds"));
        assert!(ids.contains(&"pattern.small-crates"));
        assert!(ids.contains(&"pattern.compose-structs"));
        assert!(ids.contains(&"pattern.raii-guard"));
        // Phase-3 stubs
        assert!(ids.contains(&"ffi.idiomatic-errors"));
        assert!(ids.contains(&"pattern.newtype"));
    }

    #[test]
    fn registry_get_by_id() {
        let reg = Registry::new();
        let rule = reg.get("anti.deny-warnings").unwrap();
        assert_eq!(rule.id(), "anti.deny-warnings");
    }

    #[test]
    fn registry_get_unknown_returns_none() {
        let reg = Registry::new();
        assert!(reg.get("nonexistent.rule").is_none());
    }
}
