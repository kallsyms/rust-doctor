//! Tests for the analysis module.

use std::path::PathBuf;

use rust_doctor::analysis;
use rust_doctor::diagnostic::{Category, Confidence, Finding, Location, Severity};
use rust_doctor::rules::registry::{Rule, RuleContext};

// ---------------------------------------------------------------------------
// Suppression parsing tests
// ---------------------------------------------------------------------------

#[test]
fn parse_suppression_allow_rule() {
    let content = "// rust-doctor-allow anti.deny-warnings\nfn main() {}";
    let suppressions = analysis::parse_suppressions(content);
    assert_eq!(suppressions.len(), 1);
    assert_eq!(
        suppressions[0].rule_id,
        Some("anti.deny-warnings".to_string())
    );
    assert_eq!(suppressions[0].line, 1);
}

#[test]
fn parse_suppression_allow_all() {
    let content = "// rust-doctor-allow\nfn main() {}";
    let suppressions = analysis::parse_suppressions(content);
    assert_eq!(suppressions.len(), 1);
    assert!(suppressions[0].rule_id.is_none());
    assert_eq!(suppressions[0].line, 1);
}

#[test]
fn parse_suppression_disable_next_line() {
    let content = "// rust-doctor-disable-next-line pattern.builder\nfn foo() {}";
    let suppressions = analysis::parse_suppressions(content);
    assert_eq!(suppressions.len(), 1);
    assert_eq!(suppressions[0].rule_id, Some("pattern.builder".to_string()));
    // disable-next-line applies to the NEXT line (line 2)
    assert_eq!(suppressions[0].line, 2);
}

#[test]
fn parse_suppression_disable_next_line_all() {
    let content = "// rust-doctor-disable-next-line\nfn foo() {}";
    let suppressions = analysis::parse_suppressions(content);
    assert_eq!(suppressions.len(), 1);
    assert!(suppressions[0].rule_id.is_none());
    assert_eq!(suppressions[0].line, 2);
}

#[test]
fn parse_suppression_multiple() {
    let content = r#"// rust-doctor-allow anti.deny-warnings
fn main() {}
// rust-doctor-disable-next-line pattern.builder
fn foo() {}"#;
    let suppressions = analysis::parse_suppressions(content);
    assert_eq!(suppressions.len(), 2);
    assert_eq!(
        suppressions[0].rule_id,
        Some("anti.deny-warnings".to_string())
    );
    assert_eq!(suppressions[0].line, 1);
    assert_eq!(suppressions[1].rule_id, Some("pattern.builder".to_string()));
    assert_eq!(suppressions[1].line, 4);
}

// ---------------------------------------------------------------------------
// Suppression check tests
// ---------------------------------------------------------------------------

#[test]
fn is_suppressed_rule_match() {
    let content = "// rust-doctor-allow anti.deny-warnings\nfn main() {}";
    let suppressions = analysis::parse_suppressions(content);
    // Suppression on line 1, finding on line 1
    assert!(analysis::is_suppressed(
        &suppressions,
        "anti.deny-warnings",
        Some(1)
    ));
    // Finding on a different line should not be suppressed
    assert!(!analysis::is_suppressed(
        &suppressions,
        "anti.deny-warnings",
        Some(5)
    ));
}

#[test]
fn is_suppressed_no_match() {
    let content = "// rust-doctor-allow anti.deny-warnings\nfn main() {}";
    let suppressions = analysis::parse_suppressions(content);
    assert!(!analysis::is_suppressed(
        &suppressions,
        "other.rule",
        Some(1)
    ));
}

#[test]
fn is_suppressed_no_location() {
    let content = "// rust-doctor-allow anti.deny-warnings\nfn main() {}";
    let suppressions = analysis::parse_suppressions(content);
    // No location means we can't suppress by line
    assert!(!analysis::is_suppressed(
        &suppressions,
        "anti.deny-warnings",
        None
    ));
}

#[test]
fn is_suppressed_global_allows_all() {
    let content = "// rust-doctor-allow\nfn main() {}";
    let suppressions = analysis::parse_suppressions(content);
    // Global suppression on line 1
    assert!(analysis::is_suppressed(&suppressions, "any.rule", Some(1)));
    assert!(analysis::is_suppressed(
        &suppressions,
        "other.rule",
        Some(1)
    ));
}

#[test]
fn is_line_suppressed_rule_match() {
    let suppressions = vec![analysis::Suppression {
        rule_id: Some("pattern.builder".to_string()),
        line: 10,
    }];
    assert!(analysis::is_line_suppressed(
        &suppressions,
        "pattern.builder",
        10
    ));
    assert!(!analysis::is_line_suppressed(
        &suppressions,
        "pattern.builder",
        11
    ));
    assert!(!analysis::is_line_suppressed(
        &suppressions,
        "other.rule",
        10
    ));
}

#[test]
fn is_line_suppressed_all_wildcard() {
    let suppressions = vec![analysis::Suppression {
        rule_id: Some("*".to_string()),
        line: 5,
    }];
    assert!(analysis::is_line_suppressed(&suppressions, "any.rule", 5));
    assert!(!analysis::is_line_suppressed(&suppressions, "any.rule", 6));
}

// ---------------------------------------------------------------------------
// Source location helpers
// ---------------------------------------------------------------------------

#[test]
fn find_line_found() {
    let content = "fn main() {}\nfn foo() {}";
    assert_eq!(analysis::find_line(content, "foo"), Some(2));
}

#[test]
fn find_line_not_found() {
    let content = "fn main() {}\nfn foo() {}";
    assert_eq!(analysis::find_line(content, "bar"), None);
}

#[test]
fn find_line_with_keyword() {
    let content = "impl MyStruct {\n    fn my_method() {}\n}";
    assert_eq!(
        analysis::find_line_with_keyword(content, "fn", "my_method"),
        Some(2)
    );
}

// ---------------------------------------------------------------------------
// Public API detection
// ---------------------------------------------------------------------------

#[test]
fn is_pub_true() {
    assert!(analysis::is_pub("pub"));
    assert!(analysis::is_pub("pub(crate)"));
    assert!(analysis::is_pub("pub(super)"));
}

#[test]
fn is_pub_false() {
    assert!(!analysis::is_pub(""));
    assert!(!analysis::is_pub("fn"));
}

#[test]
fn collect_pub_fn_names() {
    let file: syn::File = syn::parse_quote! {
        pub fn public_fn() {}
        fn private_fn() {}
        pub(crate) fn crate_fn() {}
    };
    let names = analysis::collect_pub_fn_names(&file.items);
    assert!(names.contains(&"public_fn".to_string()));
    assert!(names.contains(&"crate_fn".to_string()));
    assert!(!names.contains(&"private_fn".to_string()));
}

#[test]
fn collect_pub_type_names() {
    let file: syn::File = syn::parse_quote! {
        pub struct PublicStruct {}
        struct PrivateStruct {}
        pub enum PublicEnum { A }
        pub trait PublicTrait {}
    };
    let names = analysis::collect_pub_type_names(&file.items);
    assert!(names.contains(&"PublicStruct".to_string()));
    assert!(names.contains(&"PublicEnum".to_string()));
    assert!(names.contains(&"PublicTrait".to_string()));
    assert!(!names.contains(&"PrivateStruct".to_string()));
}

// ---------------------------------------------------------------------------
// Unsafe / extern detection
// ---------------------------------------------------------------------------

#[test]
fn count_unsafe() {
    let content = r#"
fn foo() {
    unsafe { }
    unsafe fn bar() {}
}
"#;
    assert_eq!(analysis::count_unsafe(content), 2);
}

#[test]
fn count_unsafe_none() {
    let content = "fn foo() {}";
    assert_eq!(analysis::count_unsafe(content), 0);
}

#[test]
fn collect_unsafe_fn_names() {
    let file: syn::File = syn::parse_quote! {
        fn safe_fn() {}
        unsafe fn unsafe_fn() {}
    };
    let names = analysis::collect_unsafe_fn_names(&file.items);
    assert_eq!(names, vec!["unsafe_fn".to_string()]);
}

#[test]
fn collect_extern_fn_names() {
    let file: syn::File = syn::parse_quote! {
        fn safe_fn() {}
        extern "C" fn ffi_fn(x: i32) -> i32 {}
    };
    let names = analysis::collect_extern_fn_names(&file.items);
    assert!(names.contains(&"ffi_fn(i32)".to_string()));
    assert!(!names.contains(&"safe_fn".to_string()));
}

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

struct TestRule;

impl Rule for TestRule {
    fn id(&self) -> &'static str {
        "test.rule"
    }
    fn title(&self) -> &'static str {
        "Test rule"
    }
    fn category(&self) -> Category {
        Category::Idiom
    }
    fn default_severity(&self) -> Severity {
        Severity::Info
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::High
    }
    fn check(&self, _ctx: &RuleContext, _out: &mut Vec<Finding>) -> anyhow::Result<()> {
        Ok(())
    }
}

#[test]
fn make_finding() {
    let rule = TestRule;
    let location = Location {
        path: PathBuf::from("src/main.rs"),
        line: Some(5),
        column: None,
        end_line: Some(5),
        end_column: None,
    };
    let finding = analysis::make_finding(
        &rule,
        location,
        "test message".to_string(),
        "test why".to_string(),
        Some("test suggestion".to_string()),
    );
    assert_eq!(finding.rule_id, "test.rule");
    assert_eq!(finding.message, "test message");
    assert_eq!(finding.suggestion, Some("test suggestion".to_string()));
}

#[test]
fn make_finding_no_location() {
    let rule = TestRule;
    let finding = analysis::make_finding_no_location(
        &rule,
        "crate-level finding".to_string(),
        "important".to_string(),
        None,
    );
    assert_eq!(finding.rule_id, "test.rule");
    assert!(finding.location.is_none());
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

#[test]
fn collect_rust_files_basic() {
    let dir = PathBuf::from("./tests/fixtures/basic");
    let mut files = Vec::new();
    analysis::collect_rust_files(&dir, &mut files);
    assert!(!files.is_empty());
    assert!(files.iter().any(|f| f.ends_with("lib.rs")));
}

#[test]
fn collect_rust_files_skips_target() {
    let dir = PathBuf::from("./tests/fixtures/negative-unsafety");
    let mut files = Vec::new();
    analysis::collect_rust_files(&dir, &mut files);
    // Should find lib.rs, sub.rs, sub2.rs, and bin/main.rs
    assert!(!files.is_empty());
}

#[test]
fn parse_file_at() {
    let path = PathBuf::from("./tests/fixtures/basic/src/lib.rs");
    let file = analysis::parse_file_at(&path);
    assert!(file.is_some());
}

#[test]
fn parse_file_invalid() {
    let result = analysis::parse_file("not valid rust {{{");
    assert!(result.is_none());
}

#[test]
fn parse_file_valid() {
    let result = analysis::parse_file("fn main() {}");
    assert!(result.is_some());
}
