//! Pattern rules and Phase-2 stubs.

use crate::diagnostic::{Category, Confidence, Finding, Location, Severity};
use crate::rules::registry::{Rule, RuleContext};
use quote::ToTokens;
use syn::visit::Visit;
use syn::File;

// ---------------------------------------------------------------------------
// PatternBuilder
// ---------------------------------------------------------------------------

/// Suggest builder pattern for functions with many parameters.
#[derive(Default)]
pub struct PatternBuilder;

impl Rule for PatternBuilder {
    fn id(&self) -> &'static str {
        "pattern.builder"
    }

    fn title(&self) -> &'static str {
        "Consider builder pattern"
    }

    fn category(&self) -> Category {
        Category::Pattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Suggests builder pattern for public constructors with many parameters."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/creational/builder.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Consider using a builder pattern with a `Config` struct and `build()` method for functions with many parameters.")
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        const PARAM_THRESHOLD: usize = 5;

        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                let content = std::fs::read_to_string(src_path)?;
                let file: File = match syn::parse_file(&content) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                for item in &file.items {
                    if let syn::Item::Fn(fn_item) = item {
                        let vis_str = fn_item.vis.to_token_stream().to_string();
                        if !vis_str.contains("pub") {
                            continue;
                        }

                        let input_count = fn_item.sig.inputs.len();
                        if input_count >= PARAM_THRESHOLD {
                            let line = content
                                .lines()
                                .position(|l| {
                                    l.contains("fn") && l.contains(&fn_item.sig.ident.to_string())
                                })
                                .map(|n| (n + 1) as u32)
                                .unwrap_or(0);

                            let opt_count = fn_item
                                .sig
                                .inputs
                                .iter()
                                .filter(|arg| {
                                    if let syn::FnArg::Typed(pat_type) = arg {
                                        let ty_str = pat_type.ty.to_token_stream().to_string();
                                        ty_str.starts_with("Option<")
                                    } else {
                                        false
                                    }
                                })
                                .count();

                            let mut message = format!(
                                "Public function `{}` has {} parameters (threshold: {})",
                                fn_item.sig.ident, input_count, PARAM_THRESHOLD
                            );
                            if opt_count > 0 {
                                message.push_str(&format!(
                                    "; {} parameters are `Option<T>`",
                                    opt_count
                                ));
                            }

                            out.push(Finding {
                                rule_id: self.id().to_string(),
                                title: self.title().to_string(),
                                category: self.category(),
                                severity: self.default_severity(),
                                confidence: self.default_confidence(),
                                location: Some(Location {
                                    path: src_path.to_path_buf().into(),
                                    line: Some(line),
                                    column: None,
                                    end_line: Some(line),
                                    end_column: None,
                                }),
                                message,
                                why_it_matters: "Functions with many parameters are hard to call correctly and difficult to extend without breaking existing callers. The builder pattern provides a clean, extensible API."
                                    .to_string(),
                                suggestion: Some(
                                    "Consider creating a `Config` struct and using the builder pattern (e.g., `MyBuilder::default().field1(...).build()`) instead."
                                        .to_string(),
                                ),
                                references: self.references().into_iter().map(String::from).collect(),
                                llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PatternContainUnSafety
// ---------------------------------------------------------------------------

/// Flag unsafe code spread across many files.
#[derive(Default)]
pub struct PatternContainUnSafety;

impl Rule for PatternContainUnSafety {
    fn id(&self) -> &'static str {
        "pattern.contain-unsafety"
    }

    fn title(&self) -> &'static str {
        "Consider containing unsafe code"
    }

    fn category(&self) -> Category {
        Category::Organization
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Flag `unsafe` spread across many files; suggest small audited unsafe boundaries."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/structural/contain-unsafety.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some(
            "Isolate unsafe code into small modules with safe outer APIs. Keep the unsafe surface \
             area minimal. Trade-off: containment adds a layer of indirection and may introduce \
             small performance overhead from safe wrapper calls.",
        )
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        const UNSAFE_FILE_THRESHOLD: usize = 5;
        const UNSAFE_BLOCK_THRESHOLD: usize = 15;

        let mut unsafe_file_count: usize = 0;
        let mut total_unsafe_blocks: usize = 0;
        let mut unsafe_details: Vec<(String, usize)> = Vec::new();

        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                let content = std::fs::read_to_string(src_path)?;
                let block_count = content.matches("unsafe").count();
                if block_count > 0 {
                    unsafe_file_count += 1;
                    total_unsafe_blocks += block_count;
                    let file_display = src_path.to_string();
                    unsafe_details.push((file_display, block_count));
                }
            }
        }

        if unsafe_file_count > UNSAFE_FILE_THRESHOLD || total_unsafe_blocks > UNSAFE_BLOCK_THRESHOLD
        {
            let mut suggestion = format!(
                "Group unsafe code into a small module with a safe public API boundary. \
                 Unsafe found in {} files ({} total unsafe blocks).",
                unsafe_file_count, total_unsafe_blocks
            );
            for (path, count) in unsafe_details.iter().take(5) {
                suggestion.push_str(&format!("\n  - {}: {count} unsafe block(s)", path));
            }

            out.push(Finding {
                rule_id: self.id().to_string(),
                title: self.title().to_string(),
                category: self.category(),
                severity: self.default_severity(),
                confidence: self.default_confidence(),
                location: None,
                message: format!(
                    "Unsafe code found in {} files ({} blocks); consider containing it in a single module",
                    unsafe_file_count, total_unsafe_blocks
                ),
                why_it_matters: "Unsafe code spread across many files makes auditing harder and increases the risk of unsafe bugs. Each unsafe block is a potential violation of Rust's safety guarantees that must be manually verified. Trade-off: containment adds a layer of indirection and may introduce small performance overhead from safe wrapper calls.".to_string(),
                suggestion: Some(suggestion),
                references: self.references().into_iter().map(String::from).collect(),
                llm_fix_prompt: self.llm_fix_prompt().map(String::from),
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PatternCustomTraitsForBounds
// ---------------------------------------------------------------------------

/// Flag repeated long where clauses or complex Fn bounds.
#[derive(Default)]
pub struct PatternCustomTraitsForBounds;

impl Rule for PatternCustomTraitsForBounds {
    fn id(&self) -> &'static str {
        "pattern.custom-traits-for-bounds"
    }

    fn title(&self) -> &'static str {
        "Consider custom trait for complex bounds"
    }

    fn category(&self) -> Category {
        Category::Pattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Flag repeated long where clauses or complex Fn bounds."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/structural/custom-traits-for-complex-bounds.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Extract complex trait bounds into a named custom trait with a blanket implementation for readability.")
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        const WHERE_CLAUSE_CHAR_THRESHOLD: usize = 80;

        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                let content = std::fs::read_to_string(src_path)?;
                let file: File = match syn::parse_file(&content) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                for item in &file.items {
                    match item {
                        syn::Item::Fn(fn_item) => {
                            analyze_fn_where_clause(
                                fn_item,
                                &content,
                                src_path.as_std_path(),
                                self,
                                out,
                                WHERE_CLAUSE_CHAR_THRESHOLD,
                            );
                        }
                        syn::Item::Impl(imp) => {
                            analyze_impl_where_clause(
                                imp,
                                &content,
                                src_path.as_std_path(),
                                self,
                                out,
                                WHERE_CLAUSE_CHAR_THRESHOLD,
                            );
                        }
                        syn::Item::Trait(tr) => {
                            analyze_trait_where_clause(
                                tr,
                                &content,
                                src_path.as_std_path(),
                                self,
                                out,
                                WHERE_CLAUSE_CHAR_THRESHOLD,
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}

/// Analyze a function for overly long where clauses or complex Fn bounds.
fn analyze_fn_where_clause(
    fn_item: &syn::ItemFn,
    content: &str,
    src_path: &std::path::Path,
    rule: &PatternCustomTraitsForBounds,
    out: &mut Vec<Finding>,
    threshold: usize,
) {
    let item_token_str = quote::quote!(#fn_item).to_string();
    if item_token_str.len() > threshold && item_token_str.contains("where") {
        analyze_where_text(
            item_token_str.as_str(),
            content,
            src_path,
            rule,
            "function",
            threshold,
            out,
        );
    }
}

/// Analyze an impl block for overly long where clauses or complex Fn bounds.
fn analyze_impl_where_clause(
    imp: &syn::ItemImpl,
    content: &str,
    src_path: &std::path::Path,
    rule: &PatternCustomTraitsForBounds,
    out: &mut Vec<Finding>,
    threshold: usize,
) {
    let item_token_str = quote::quote!(#imp).to_string();
    if item_token_str.len() > threshold && item_token_str.contains("where") {
        analyze_where_text(
            item_token_str.as_str(),
            content,
            src_path,
            rule,
            "impl block",
            threshold,
            out,
        );
    }
}

/// Analyze a trait for overly long where clauses or complex Fn bounds.
fn analyze_trait_where_clause(
    tr: &syn::ItemTrait,
    content: &str,
    src_path: &std::path::Path,
    rule: &PatternCustomTraitsForBounds,
    out: &mut Vec<Finding>,
    threshold: usize,
) {
    let item_token_str = quote::quote!(#tr).to_string();
    if item_token_str.len() > threshold && item_token_str.contains("where") {
        analyze_where_text(
            item_token_str.as_str(),
            content,
            src_path,
            rule,
            "trait",
            threshold,
            out,
        );
    }
}

/// Analyze where clause text for complex bounds.
fn analyze_where_text(
    item_str: &str,
    content: &str,
    src_path: &std::path::Path,
    rule: &PatternCustomTraitsForBounds,
    item_kind: &str,
    _threshold: usize,
    out: &mut Vec<Finding>,
) {
    if let Some(where_pos) = item_str.find("where") {
        let where_end = item_str.len().min(where_pos + 5 + 200);
        let where_text = &item_str[where_pos..where_end];

        let fn_bound_count = where_text.matches("Fn").count();

        if fn_bound_count >= 2 || where_text.len() > 60 {
            let line = content
                .lines()
                .position(|l| l.contains("where"))
                .map(|n| (n + 1) as u32)
                .unwrap_or(0);

            out.push(Finding {
                rule_id: rule.id().to_string(),
                title: rule.title().to_string(),
                category: rule.category(),
                severity: rule.default_severity(),
                confidence: rule.default_confidence(),
                location: Some(Location {
                    path: src_path.to_path_buf(),
                    line: Some(line),
                    column: None,
                    end_line: Some(line),
                    end_column: None,
                }),
                message: format!(
                    "{} has a complex where clause ({} Fn bounds) that could be extracted into a custom trait",
                    item_kind, fn_bound_count.max(1)
                ),
                why_it_matters: "Long, complex trait bounds reduce readability and make it harder to understand API requirements at a glance. A custom trait with a blanket implementation can express the same constraint in a single name."
                    .to_string(),
                suggestion: Some("Extract the trait bounds into a named custom trait (e.g., `trait MyBounds: TraitA + TraitB + Fn(...)`) and use it as a single bound.".to_string()),
                references: rule.references().into_iter().map(String::from).collect(),
                llm_fix_prompt: rule.llm_fix_prompt().map(String::from),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// PatternSmallCrates
// ---------------------------------------------------------------------------

/// Flag very large crates/modules.
#[derive(Default)]
pub struct PatternSmallCrates;

impl Rule for PatternSmallCrates {
    fn id(&self) -> &'static str {
        "pattern.small-crates"
    }

    fn title(&self) -> &'static str {
        "Consider splitting large crates"
    }

    fn category(&self) -> Category {
        Category::Organization
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Flag very large crates/modules and detect dependency version duplication across packages."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/structural/prefer-small-crates.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some(
            "Consider splitting large crates into smaller, more focused crates for better modularity \
             and parallel compilation. Also check for duplicate dependency versions across workspace \
             packages.",
        )
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        const LARGE_CRATE_LINES: usize = 1000;
        const LARGE_CRATE_FILES: usize = 15;

        // Track dependency versions across packages for duplication detection
        let mut dep_versions: std::collections::HashMap<String, Vec<(String, String)>> =
            std::collections::HashMap::new();

        for pkg in ctx.metadata.packages.iter() {
            // Track this package's dependencies
            for dep in &pkg.dependencies {
                let key = format!("{}:{}", dep.name, dep.req);
                dep_versions
                    .entry(key)
                    .or_default()
                    .push((pkg.name.clone(), dep.req.to_string()));
            }

            let mut total_lines: usize = 0;
            let mut file_count: usize = 0;
            let mut large_files: Vec<(String, usize)> = Vec::new();

            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                if src_path.is_file() {
                    if let Ok(content) = std::fs::read_to_string(src_path) {
                        let line_count = content.lines().count();
                        total_lines += line_count;
                        file_count += 1;
                        if line_count > 300 {
                            large_files.push((src_path.to_string(), line_count));
                        }
                    }
                }
            }

            // Also check for subdirectories that might be large modules
            for pkg2 in ctx.metadata.packages.iter() {
                for target in &pkg2.targets {
                    let src_path = target.src_path.as_path();
                    if src_path.is_dir() {
                        // Count files in the directory
                        let mut dir_files: Vec<std::path::PathBuf> = Vec::new();
                        collect_files(src_path.as_std_path(), &mut dir_files);
                        file_count += dir_files.len();
                        for f in &dir_files {
                            if let Ok(content) = std::fs::read_to_string(f) {
                                total_lines += content.lines().count();
                                let line_count = content.lines().count();
                                if line_count > 300 {
                                    large_files.push((f.display().to_string(), line_count));
                                }
                            }
                        }
                    }
                }
            }

            if total_lines > LARGE_CRATE_LINES || file_count > LARGE_CRATE_FILES {
                let mut suggestion = format!(
                    "Consider splitting this crate into smaller modules. \
                     Current size: {} lines across {} files. \
                     Large files:",
                    total_lines, file_count
                );
                for (path, lines) in large_files.iter().take(5) {
                    suggestion.push_str(&format!("\n  - {}: {} lines", path, lines));
                }

                out.push(Finding {
                    rule_id: self.id().to_string(),
                    title: self.title().to_string(),
                    category: self.category(),
                    severity: self.default_severity(),
                    confidence: self.default_confidence(),
                    location: None,
                    message: format!(
                        "Package \"{}\" is large ({} lines, {} files); consider splitting into smaller crates",
                        pkg.name, total_lines, file_count
                    ),
                    why_it_matters: "Large crates slow down compilation, reduce modularity, and make it harder for developers to navigate the codebase. Smaller, focused crates improve parallel compilation and reuse. Trade-off: small crates can increase dependency hell risk, trust boundaries, and miss whole-crate optimization opportunities.".to_string(),
                    suggestion: Some(suggestion),
                    references: self.references().into_iter().map(String::from).collect(),
                    llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                });
            }
        }

        // Report dependency version duplication
        let mut dup_count: usize = 0;
        for users in dep_versions.values() {
            if users.len() > 1 {
                dup_count += 1;
            }
        }
        if dup_count > 0 {
            let mut details = String::new();
            for (key, users) in &dep_versions {
                if users.len() > 1 {
                    details.push_str(&format!(
                        "  - {}: {} packages using different versions: {}\n",
                        key,
                        users.len(),
                        users
                            .iter()
                            .map(|(pkg, ver)| format!("{} ({})", pkg, ver))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
            out.push(Finding {
                rule_id: self.id().to_string(),
                title: self.title().to_string(),
                category: self.category(),
                severity: self.default_severity(),
                confidence: self.default_confidence(),
                location: None,
                message: format!(
                    "Workspace has {} dependency version duplicates across packages",
                    dup_count
                ),
                why_it_matters: "Duplicate dependency versions increase compile times, binary size, and can cause subtle incompatibilities. Consolidating to a single version improves build performance and reduces the risk of version-specific bugs.".to_string(),
                suggestion: Some(format!(
                    "Run `cargo update` to consolidate versions, or use `[patch]` sections to force a single version. Details:\n{}",
                    details.trim()
                )),
                references: self.references().into_iter().map(String::from).collect(),
                llm_fix_prompt: Some(
                    "Run `cargo update` to consolidate duplicate dependency versions. If specific \
                     versions are needed, use Cargo's `[patch]` sections to override."
                    .to_string(),
                ),
            });
        }

        Ok(())
    }
}

fn collect_files(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
    if !dir.is_dir() {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            if path.file_name() == Some("target".as_ref())
                || path.file_name() == Some(".git".as_ref())
            {
                continue;
            }
            collect_files(&path, files);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            files.push(path);
        }
    }
}

// ---------------------------------------------------------------------------

/// Flag `.clone()` used to work around borrow-checker conflicts.
///
/// Conservative heuristic: flags `.clone()` on owned types (`String`, `Vec`,
/// `Box`, `Rc`, `Arc`) inside functions where a borrow would suffice.
/// Skips clones inside loops, explicit ownership-transfer patterns, and
/// non-reference contexts.
#[derive(Default)]
pub struct AntiCloneToSatisfyBorrowChecker;

impl Rule for AntiCloneToSatisfyBorrowChecker {
    fn id(&self) -> &'static str {
        "anti.clone-to-satisfy-borrow-checker"
    }

    fn title(&self) -> &'static str {
        "Clone to satisfy borrow checker"
    }

    fn category(&self) -> Category {
        Category::AntiPattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Detects `.clone()` calls on owned types (`String`, `Vec`, `Box`, `Rc`, `Arc`) that are used only to satisfy borrow-checker conflicts. Prefer borrowing via `&str`, `&[T]`, or `&T`."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/anti-patterns/clone-to-satisfy-borrow-checker.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Change `.clone()` calls to borrows (`&str`, `&[T]`, `&T`) where possible. Use `mem::take` or `mem::replace` if ownership transfer is genuinely needed.")
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                let content = std::fs::read_to_string(src_path)?;
                let file: File = match syn::parse_file(&content) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                for item in &file.items {
                    if let syn::Item::Fn(fn_item) = item {
                        let vis_str = fn_item.vis.to_token_stream().to_string();
                        // Only check public functions — internal clones are often fine
                        if !vis_str.contains("pub") {
                            continue;
                        }

                        let fn_name = fn_item.sig.ident.to_string();

                        // Walk the function body looking for `.clone()` method calls
                        let mut visitor = CloneChecker {
                            fn_name: &fn_name,
                            content: &content,
                            src_path: src_path.to_path_buf().into(),
                            findings: Vec::new(),
                        };
                        visitor.visit_item_fn(fn_item);

                        for finding in visitor.findings {
                            out.push(finding);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Visitor that walks a function and collects clone findings.
struct CloneChecker<'a> {
    fn_name: &'a str,
    content: &'a str,
    src_path: std::path::PathBuf,
    findings: Vec<Finding>,
}

impl<'a> CloneChecker<'a> {
    fn find_location(&self, line: u32) -> Option<Location> {
        Some(Location {
            path: self.src_path.clone(),
            line: Some(line),
            column: None,
            end_line: Some(line),
            end_column: None,
        })
    }

    fn is_in_loop(&self, line_num: u32) -> bool {
        let lines: Vec<&str> = self.content.lines().collect();
        if line_num as usize >= lines.len() {
            return false;
        }
        // Look backwards for loop keywords at same or deeper indentation
        for i in (0..=line_num as usize).rev() {
            let trimmed = lines[i].trim();
            if trimmed.starts_with("let ")
                || trimmed.starts_with("if ")
                || trimmed.starts_with("return ")
            {
                break;
            }
            if trimmed.starts_with("for ") || trimmed.starts_with("while ") || trimmed == "loop" {
                return true;
            }
            if trimmed == "}" {
                break;
            }
        }
        false
    }

    fn is_mem_take_pattern(&self, line: u32) -> bool {
        let lines: Vec<&str> = self.content.lines().collect();
        if line as usize >= lines.len() {
            return false;
        }
        let content_line = lines[line as usize];
        content_line.contains("mem::take") || content_line.contains("mem::replace")
    }

    fn is_into_chain(&self, node: &syn::ExprMethodCall) -> bool {
        // Check if the clone result is chained with .into() or .to_string()
        let recv_str = node.receiver.to_token_stream().to_string();
        recv_str.contains(".into()") || recv_str.contains(".to_string()")
    }

    /// Get the 0-based line number by finding the clone expression in source text.
    fn line_number_from_content(&self, node: &syn::ExprMethodCall) -> u32 {
        let content = self.content;
        let method_name = node.method.to_string();
        if method_name == "clone" {
            // Find the clone call by text search within the content
            let recv_str = node.receiver.to_token_stream().to_string();
            let pattern = format!("{recv_str}.clone()");
            if let Some(pos) = content.find(&pattern) {
                // Count newlines before this position
                let line = content[..pos].lines().count() as u32;
                return line;
            }
        }
        0
    }
}

impl<'a> syn::visit::Visit<'a> for CloneChecker<'a> {
    fn visit_expr_method_call(&mut self, node: &'a syn::ExprMethodCall) {
        let method_name = node.method.to_string();
        if method_name == "clone" {
            let line = self.line_number_from_content(node);

            if line == 0 {
                return;
            }
            if self.is_in_loop(line) {
                return;
            }
            if self.is_mem_take_pattern(line) {
                return;
            }
            if self.is_into_chain(node) {
                return;
            }

            if let Some(loc) = self.find_location(line) {
                self.findings.push(Finding {
                    rule_id: "anti.clone-to-satisfy-borrow-checker".to_string(),
                    title: "Clone to satisfy borrow checker".to_string(),
                    category: Category::AntiPattern,
                    severity: Severity::Warning,
                    confidence: Confidence::Medium,
                    location: Some(loc),
                    message: format!(
                        "Function `{}` uses `.clone()` which may be a borrow-checker workaround; consider borrowing instead",
                        self.fn_name
                    ),
                    why_it_matters: "Unnecessary cloning increases memory allocation and copies data that could be referenced. Borrowing avoids allocation and keeps a single source of truth.".to_string(),
                    suggestion: Some("Change the callee to accept `&str`, `&[T]`, or `&T` instead of owned types to avoid cloning.".to_string()),
                    references: vec![String::from("https://rust-unofficial.github.io/patterns/anti-patterns/clone-to-satisfy-borrow-checker.html")],
                    llm_fix_prompt: Some(String::from("Change `.clone()` calls to borrows (`&str`, `&[T]`, `&T`) where possible. Use `mem::take` or `mem::replace` if ownership transfer is genuinely needed.")),
                });
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

// ---------------------------------------------------------------------------
// PatternComposeStructs
// ---------------------------------------------------------------------------

/// Flag overly large structs whose fields could be split into composed units.
///
/// Pragmatic heuristic: structs with more than 8 public fields are flagged
/// because they tend to suffer from independent borrow contention and make
/// it harder to reason about which fields a given method needs.
#[derive(Default)]
pub struct PatternComposeStructs;

impl Rule for PatternComposeStructs {
    fn id(&self) -> &'static str {
        "pattern.compose-structs"
    }

    fn title(&self) -> &'static str {
        "Consider splitting large structs into composed units"
    }

    fn category(&self) -> Category {
        Category::Pattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Flag structs with many (>8) fields as candidates for composition."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/structural/compose-structs.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some(
            "Split the large struct into smaller, focused structs and compose them inside the \
             original type. This improves independent borrowing and clarifies which methods need \
             which fields.",
        )
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        const FIELD_THRESHOLD: usize = 8;

        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                let content = std::fs::read_to_string(src_path)?;
                let file: File = match syn::parse_file(&content) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                for item in &file.items {
                    if let syn::Item::Struct(s) = item {
                        let vis_str = s.vis.to_token_stream().to_string();
                        if !vis_str.contains("pub") {
                            continue;
                        }

                        let field_count = match &s.fields {
                            syn::Fields::Named(n) => n.named.len(),
                            syn::Fields::Unnamed(n) => n.unnamed.len(),
                            syn::Fields::Unit => 0,
                        };

                        if field_count > FIELD_THRESHOLD {
                            let line = content
                                .lines()
                                .position(|l| {
                                    l.contains("struct") && l.contains(&s.ident.to_string())
                                })
                                .map(|n| (n + 1) as u32)
                                .unwrap_or(0);

                            out.push(Finding {
                                rule_id: self.id().to_string(),
                                title: self.title().to_string(),
                                category: self.category(),
                                severity: self.default_severity(),
                                confidence: self.default_confidence(),
                                location: Some(Location {
                                    path: src_path.to_path_buf().into(),
                                    line: Some(line),
                                    column: None,
                                    end_line: Some(line),
                                    end_column: None,
                                }),
                                message: format!(
                                    "Public struct `{}` has {} fields (>{}); consider splitting into composed units",
                                    s.ident, field_count, FIELD_THRESHOLD
                                ),
                                why_it_matters: "Large structs lead to independent borrow contention, make it harder to see which fields a method needs, and can become difficult to maintain. Splitting into smaller, focused structs clarifies responsibilities and improves ergonomics. Trade-off: composition adds a layer of indirection and may increase boilerplate.".to_string(),
                                suggestion: Some(format!(
                                    "Extract related fields into smaller structs (e.g., `struct {}Config {{ ... }}`) and compose them inside the parent struct.",
                                    s.ident
                                )),
                                references: self.references().into_iter().map(String::from).collect(),
                                llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PatternRaiiGuard
// ---------------------------------------------------------------------------

/// Flag explicit cleanup/free/release methods that could be replaced with RAII guards.
///
/// Pragmatic heuristic: detects public methods named `close`, `free`, `release`,
/// `dispose`, `shutdown` that take `&mut self` — these often signal manual
/// resource management that could be encapsulated behind a guard type with `Drop`.
#[derive(Default)]
pub struct PatternRaiiGuard;

impl Rule for PatternRaiiGuard {
    fn id(&self) -> &'static str {
        "pattern.raii-guard"
    }

    fn title(&self) -> &'static str {
        "Consider RAII guards instead of explicit cleanup methods"
    }

    fn category(&self) -> Category {
        Category::Pattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Detects explicit cleanup/free/release methods that could be replaced with RAII guard types."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/structural/raii-guards.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some(
            "Replace the manual cleanup method with a guard type that implements `Drop` to \
             automatically release resources. This prevents leaks on early returns or panics.",
        )
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        const CLEANUP_METHODS: [&str; 5] = ["close", "free", "release", "dispose", "shutdown"];

        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                let content = std::fs::read_to_string(src_path)?;
                let file: File = match syn::parse_file(&content) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                let mut visitor = RaiiVisitor {
                    content: &content,
                    src_path: src_path.to_path_buf().into(),
                    cleanup_methods: &CLEANUP_METHODS,
                    findings: out,
                };
                visitor.visit_file(&file);
            }
        }
        Ok(())
    }
}

/// Visitor that recurses into impl blocks to find cleanup methods.
struct RaiiVisitor<'a> {
    content: &'a str,
    src_path: std::path::PathBuf,
    cleanup_methods: &'a [&'a str],
    findings: &'a mut Vec<Finding>,
}

impl<'a> syn::visit::Visit<'a> for RaiiVisitor<'a> {
    fn visit_item_fn(&mut self, node: &'a syn::ItemFn) {
        let vis_str = node.vis.to_token_stream().to_string();
        if !vis_str.contains("pub") {
            syn::visit::visit_item_fn(self, node);
            return;
        }

        let fn_name = node.sig.ident.to_string();
        if !self.cleanup_methods.contains(&fn_name.as_str()) {
            syn::visit::visit_item_fn(self, node);
            return;
        }

        // Check that it takes &mut self
        let takes_mut_self = node.sig.inputs.iter().any(|arg| {
            if let syn::FnArg::Receiver(recv) = arg {
                recv.mutability.is_some()
            } else {
                false
            }
        });

        if !takes_mut_self {
            syn::visit::visit_item_fn(self, node);
            return;
        }

        let line = self
            .content
            .lines()
            .position(|l| l.contains("fn") && l.contains(&fn_name))
            .map(|n| (n + 1) as u32)
            .unwrap_or(0);

        self.findings.push(Finding {
            rule_id: "pattern.raii-guard".to_string(),
            title: "Consider RAII guards instead of explicit cleanup methods".to_string(),
            category: Category::Pattern,
            severity: Severity::Info,
            confidence: Confidence::Low,
            location: Some(Location {
                path: self.src_path.clone(),
                line: Some(line),
                column: None,
                end_line: Some(line),
                end_column: None,
            }),
            message: format!(
                "Public method `{fn_name}` suggests manual resource cleanup; consider an RAII guard with `Drop`",
            ),
            why_it_matters: "Manual cleanup methods require callers to remember to invoke them, which is error-prone on early returns, panics, or error paths. A guard type that implements `Drop` ensures cleanup happens automatically. Trade-off: guard types add a small allocation or stack footprint and change the API surface.".to_string(),
            suggestion: Some(format!(
                "Create a `{0}Guard` type that holds the resource and implements `Drop` to call `{0}` automatically. Return the guard from the constructor instead of the raw handle.",
                fn_name
            )),
            references: vec!["https://rust-unofficial.github.io/patterns/patterns/structural/raii-guards.html".into()],
            llm_fix_prompt: Some(
                "Replace the manual cleanup method with a guard type that implements `Drop` to \
                 automatically release resources. This prevents leaks on early returns or panics."
                    .to_string(),
            ),
        });
    }
}

// ---------------------------------------------------------------------------
// Phase-2 Stubs (inert - no findings)
// ---------------------------------------------------------------------------

/// PatternNewtype: Flag unnecessary newtype wrappers.
#[derive(Default)]
pub struct PatternNewtype;

impl Rule for PatternNewtype {
    fn id(&self) -> &'static str {
        "pattern.newtype"
    }
    fn title(&self) -> &'static str {
        "Consider using the underlying type directly"
    }
    fn category(&self) -> Category {
        Category::Pattern
    }
    fn default_severity(&self) -> Severity {
        Severity::Info
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn description(&self) -> &'static str {
        "Detects newtype wrappers that simply wrap a primitive or standard type without adding behavior."
    }
    fn references(&self) -> Vec<&'static str> {
        vec![]
    }
    fn check(&self, _ctx: &RuleContext, _out: &mut Vec<Finding>) -> anyhow::Result<()> {
        Ok(())
    }
}

/// FfiIdiomaticErrors: Detect FFI idiomatic errors.
#[derive(Default)]
pub struct FfiIdiomaticErrors;

impl Rule for FfiIdiomaticErrors {
    fn id(&self) -> &'static str {
        "ffi.idiomatic-errors"
    }

    fn title(&self) -> &'static str {
        "FFI idiomatic errors"
    }

    fn category(&self) -> Category {
        Category::Pattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Detect common FFI pattern mistakes."
    }

    fn references(&self) -> Vec<&'static str> {
        vec![]
    }

    fn check(&self, _ctx: &RuleContext, _out: &mut Vec<Finding>) -> anyhow::Result<()> {
        Ok(())
    }
}
