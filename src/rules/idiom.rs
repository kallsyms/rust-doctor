//! Idiom rules: borrowed-args, default-trait, option-iteration, privacy-extensibility.

use crate::diagnostic::{Category, Confidence, Finding, Location, Severity};
use crate::rules::registry::{Rule, RuleContext};
use quote::ToTokens;
use syn::visit::Visit;
use syn::{File, FnArg, ItemFn, Stmt, Type};

// ---------------------------------------------------------------------------
// IdiomBorrowedArgs
// ---------------------------------------------------------------------------

/// Flag borrowed owned types in function parameters.
#[derive(Default)]
pub struct IdiomBorrowedArgs;

impl Rule for IdiomBorrowedArgs {
    fn id(&self) -> &'static str {
        "idiom.borrowed-args"
    }

    fn title(&self) -> &'static str {
        "Use borrowed types for arguments"
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

    fn description(&self) -> &'static str {
        "Suggests `&str`, `&Path`, `&[T]`, and `&T` over `&String`, `&PathBuf`, `&Vec<T>`, and `&Box<T>` in function parameters."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/idioms/use-borrowed-types-for-arguments.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Change function parameters from `&String` to `&str`, `&Vec<T>` to `&[T]`, `&PathBuf` to `&Path`, and `&Box<T>` to `&T` to widen accepted callers.")
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
                let mut visitor = BorrowedArgsVisitor {
                    findings: Vec::new(),
                    content,
                };
                visitor.visit_file(&file);
                for finding in visitor.findings {
                    out.push(Finding {
                        rule_id: self.id().to_string(),
                        title: self.title().to_string(),
                        category: self.category(),
                        severity: self.default_severity(),
                        confidence: self.default_confidence(),
                        location: Some(Location {
                            path: src_path.to_path_buf().into(),
                            line: Some(finding.line),
                            column: None,
                            end_line: Some(finding.line),
                            end_column: None,
                        }),
                        message: format!("`{}` is a borrowed owned type; prefer `{}`", finding.borrowed, finding.suggested),
                        why_it_matters: "Borrowed owned types reduce the number of callers that can invoke the API and add unnecessary indirection.".to_string(),
                        suggestion: Some(format!("Consider using `{}` instead of `{}`", finding.suggested, finding.borrowed)),
                        references: self.references().into_iter().map(String::from).collect(),
                        llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                    });
                }
            }
        }
        Ok(())
    }
}

struct BorrowedArgFinding {
    line: u32,
    borrowed: String,
    suggested: String,
}

struct BorrowedArgsVisitor {
    findings: Vec<BorrowedArgFinding>,
    content: String,
}

impl<'a> Visit<'a> for BorrowedArgsVisitor {
    fn visit_item_fn(&mut self, item: &'a ItemFn) {
        // Check if function is pub or pub(crate)
        let vis_str = item.vis.to_token_stream().to_string();
        if !vis_str.contains("pub") {
            return;
        }

        for arg in &item.sig.inputs {
            if let FnArg::Typed(pat_type) = arg {
                if let Type::Reference(ref_type) = pat_type.ty.as_ref() {
                    if let Type::Path(type_path) = ref_type.elem.as_ref() {
                        let seg = type_path.path.segments.last();
                        if let Some(seg) = seg {
                            let owned_type = seg.ident.to_string();
                            let suggested = match owned_type.as_str() {
                                "String" => "str",
                                "Vec" => "[T]",
                                "PathBuf" => "Path",
                                "Box" => "T",
                                _ => continue,
                            };
                            // Find the line in the source content
                            let line = self
                                .content
                                .lines()
                                .position(|l| l.contains(&owned_type))
                                .map(|n| (n + 1) as u32)
                                .unwrap_or(0);
                            self.findings.push(BorrowedArgFinding {
                                line,
                                borrowed: owned_type.clone(),
                                suggested: format!("&{}", suggested),
                            });
                        }
                    }
                }
            }
        }

        syn::visit::visit_item_fn(self, item);
    }
}

// ---------------------------------------------------------------------------
// IdiomDefaultTrait
// ---------------------------------------------------------------------------

/// Suggest deriving/implementing Default when zero-arg new() returns defaults.
#[derive(Default)]
pub struct IdiomDefaultTrait;

impl Rule for IdiomDefaultTrait {
    fn id(&self) -> &'static str {
        "idiom.default-trait"
    }

    fn title(&self) -> &'static str {
        "Consider implementing Default"
    }

    fn category(&self) -> Category {
        Category::Idiom
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Suggests deriving/implementing `Default` when a zero-arg `new()` returns constant/default field values."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/idioms/the-default-trait.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some(
            "Derive Default if all fields support it, or implement Default with sensible defaults.",
        )
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

                // Collect types that already derive or implement Default
                let mut has_default: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                for item in &file.items {
                    match item {
                        syn::Item::Impl(imp) => {
                            if let Some((_, path, _)) = &imp.trait_ {
                                if path
                                    .segments
                                    .last()
                                    .map(|s| s.ident == "Default")
                                    .unwrap_or(false)
                                {
                                    let self_name =
                                        extract_type_name(imp.self_ty.as_ref()).unwrap_or_default();
                                    has_default.insert(self_name);
                                }
                            }
                        }
                        syn::Item::Struct(s) => {
                            if has_default_attr(&s.attrs) {
                                has_default.insert(s.ident.to_string());
                            }
                        }
                        _ => {}
                    }
                }

                // Find zero-arg pub fn new() -> Self in inherent impls
                for item in &file.items {
                    if let syn::Item::Impl(imp) = item {
                        if imp.trait_.is_none() {
                            for impl_item in &imp.items {
                                if let syn::ImplItem::Fn(method) = impl_item {
                                    if method.sig.ident == "new"
                                        && method.sig.inputs.is_empty()
                                        && type_name_of_self_return(&method.sig.output)
                                    {
                                        let self_name = type_name(imp.self_ty.as_ref());
                                        // Skip if type already has Default
                                        if has_default.contains(&self_name) {
                                            continue;
                                        }
                                        // Check if body looks like default-like construction
                                        if is_default_like_body(&method.block) {
                                            let line = find_fn_line(
                                                &content,
                                                &method.sig.ident,
                                                &self_name,
                                            );
                                            out.push(Finding {
                                                rule_id: self.id().to_string(),
                                                title: self.title().to_string(),
                                                category: self.category(),
                                                severity: self.default_severity(),
                                                confidence: self.default_confidence(),
                                                location: Some(Location {
                                                    path: src_path.to_path_buf().into(),
                                                    line,
                                                    column: None,
                                                    end_line: line,
                                                    end_column: None,
                                                }),
                                                message: format!(
                                                    "`{}` has a zero-arg `new()` returning default-like values but does not implement `Default`",
                                                    self_name
                                                ),
                                                why_it_matters: "Implementing `Default` enables generic container APIs (`T: Default`), `*_or_default` combinators, and is the conventional way to express a no-argument default in Rust."
                                                                    .to_string(),
                                                suggestion: Some(
                                                    "Derive `Default` if all fields support it (add `#[derive(Default)]`), or implement `Default` manually with sensible defaults."
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
                    }
                }
            }
        }
        Ok(())
    }
}

fn has_default_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if a.path().is_ident("derive") {
            // Check if "Default" is in the derive list
            let attr_str = a.to_token_stream().to_string();
            return attr_str.contains("Default");
        }
        false
    })
}

fn extract_type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Reference(r) => extract_type_name(r.elem.as_ref()),
        syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        syn::Type::Slice(s) => Some(format!(
            "[{}]",
            extract_type_name(&s.elem).unwrap_or_default()
        )),
        _ => None,
    }
}

fn type_name(ty: &syn::Type) -> String {
    extract_type_name(ty).unwrap_or_else(|| "<unknown>".to_string())
}

fn type_name_of_self_return(output: &syn::ReturnType) -> bool {
    match output {
        syn::ReturnType::Type(_, ty) => extract_type_name(ty.as_ref())
            .map(|n| n == "Self")
            .unwrap_or(false),
        syn::ReturnType::Default => false,
    }
}

/// Heuristic: does the function body look like it returns default-like values?
fn is_default_like_body(block: &syn::Block) -> bool {
    if block.stmts.len() != 1 {
        return false;
    }
    match &block.stmts[0] {
        Stmt::Expr(syn::Expr::Return(ret), _) => {
            if let Some(expr) = &ret.expr {
                if let syn::Expr::Path(path) = expr.as_ref() {
                    return path.path.segments.last().is_some_and(|s| s.ident == "Self");
                }
            }
            false
        }
        Stmt::Expr(syn::Expr::Path(path), _) => {
            // Self::default() or Self { ... }
            path.path.segments.last().is_some_and(|s| s.ident == "Self")
        }
        _ => false,
    }
}

fn find_fn_line(content: &str, fn_name: &syn::Ident, self_name: &str) -> Option<u32> {
    let ident = fn_name.to_string();
    content
        .lines()
        .position(|l| l.contains("fn") && l.contains(&ident) && l.contains(self_name))
        .or_else(|| {
            content
                .lines()
                .position(|l| l.contains(&format!("fn {}()", ident)))
        })
        .map(|n| (n + 1) as u32)
}

// ---------------------------------------------------------------------------
// IdiomOptionIteration
// ---------------------------------------------------------------------------

/// Narrowly flag for loops over Option.
#[derive(Default)]
pub struct IdiomOptionIteration;

impl Rule for IdiomOptionIteration {
    fn id(&self) -> &'static str {
        "idiom.option-iteration"
    }

    fn title(&self) -> &'static str {
        "Avoid for loops over Option"
    }

    fn category(&self) -> Category {
        Category::Idiom
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Narrowly flags `for` loops over `Option` and suggests `if let Some(..)`."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/idioms/iterating-over-an-option.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Replace `for x in option {}` with `if let Some(x) = option {}` for clarity.")
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
                        let mut visitor = OptionIterationVisitor {
                            findings: Vec::new(),
                            content: &content,
                        };
                        visitor.visit_item_fn(fn_item);
                        for finding in visitor.findings {
                            out.push(Finding {
                                rule_id: self.id().to_string(),
                                title: self.title().to_string(),
                                category: self.category(),
                                severity: self.default_severity(),
                                confidence: self.default_confidence(),
                                location: Some(Location {
                                    path: src_path.to_path_buf().into(),
                                    line: Some(finding.line),
                                    column: None,
                                    end_line: Some(finding.line),
                                    end_column: None,
                                }),
                                message: "For loop over `Option` is usually less idiomatic than `if let Some(..)`"
                                    .to_string(),
                                why_it_matters: "Option implements IntoIterator, so `for x in option` works, but it is unusual and surprising. `if let Some(x) = option` is clearer and more idiomatic."
                                    .to_string(),
                                suggestion: Some(
                                    "Replace `for x in option {}` with `if let Some(x) = option {}`."
                                        .to_string()
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

struct OptionIterationFinding {
    line: u32,
}

struct OptionIterationVisitor<'a> {
    findings: Vec<OptionIterationFinding>,
    content: &'a str,
}

impl<'a> syn::visit::Visit<'a> for OptionIterationVisitor<'a> {
    fn visit_expr_for_loop(&mut self, loop_expr: &'a syn::ExprForLoop) {
        // Check if the iterator expression looks like an Option
        if is_option_expr(&loop_expr.expr) {
            let line = self
                .content
                .lines()
                .position(|l| l.contains("for"))
                .map(|n| (n + 1) as u32)
                .unwrap_or(0);
            self.findings.push(OptionIterationFinding { line });
        }
        syn::visit::visit_expr_for_loop(self, loop_expr);
    }
}

/// Heuristic: does the expression look like it could be an Option?
fn is_option_expr(expr: &syn::Expr) -> bool {
    match expr {
        // Direct Some/None literals
        syn::Expr::Call(call) => {
            if let syn::Expr::Path(path) = call.func.as_ref() {
                path.path
                    .segments
                    .last()
                    .map(|s| s.ident == "Some" || s.ident == "None")
                    .unwrap_or(false)
            } else {
                false
            }
        }
        // Identifier that might be an Option local
        syn::Expr::Path(path) => {
            path.path.segments.len() == 1
                && !path.path.segments[0]
                    .ident
                    .to_string()
                    .chars()
                    .next()
                    .unwrap_or(' ')
                    .is_uppercase()
        }
        // Method call like option.as_ref() or .iter() which returns Option
        syn::Expr::MethodCall(method) => {
            let method_name = method.method.to_string();
            // If the receiver looks like an Option identifier and the method
            // returns an Option (or the method itself is suspicious)
            matches!(method_name.as_str(), "as_ref" | "as_mut")
                || is_option_expr(method.receiver.as_ref())
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// IdiomPrivacyExtensibility
// ---------------------------------------------------------------------------

/// Flag public structs/enums without #[non_exhaustive] in library crates.
#[derive(Default)]
pub struct IdiomPrivacyExtensibility;

impl Rule for IdiomPrivacyExtensibility {
    fn id(&self) -> &'static str {
        "idiom.privacy-extensibility"
    }

    fn title(&self) -> &'static str {
        "Consider #[non_exhaustive] for public types"
    }

    fn category(&self) -> Category {
        Category::Idiom
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "For library crates, flags public structs/enums that expose fully exhaustive construction/matching."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/idioms/privacy-for-extensibility.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Consider adding `#[non_exhaustive]` to public structs/enums to preserve semver flexibility for future field/variant additions.")
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        // Check if any package appears to be a library (not binary)
        let is_library = ctx.metadata.packages.iter().any(|pkg| {
            pkg.targets
                .iter()
                .any(|t| t.kind.iter().any(|k| k == "lib"))
        });

        if !is_library {
            return Ok(());
        }

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
                        syn::Item::Struct(s) => {
                            let vis_str = s.vis.to_token_stream().to_string();
                            if vis_str.contains("pub")
                                && all_fields_pub(&s.fields)
                                && !has_non_exhaustive(&s.attrs)
                            {
                                if let Some(line) = find_struct_line(&content, &s.ident) {
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
                                        message: format!("Public struct `{}` has all public fields and no `#[non_exhaustive]`", s.ident),
                                        why_it_matters: "All-public fields make it harder to add fields in a semver-compatible way.".to_string(),
                                        suggestion: Some("Consider adding `#[non_exhaustive]` to allow future field additions.".to_string()),
                                        references: self.references().into_iter().map(String::from).collect(),
                                        llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                                    });
                                }
                            }
                        }
                        syn::Item::Enum(e) => {
                            let vis_str = e.vis.to_token_stream().to_string();
                            if vis_str.contains("pub") && !has_non_exhaustive(&e.attrs) {
                                if let Some(line) = find_enum_line(&content, &e.ident) {
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
                                        message: format!("Public enum `{}` has no `#[non_exhaustive]`", e.ident),
                                        why_it_matters: "Exhaustive enums make it harder to add variants in a semver-compatible way.".to_string(),
                                        suggestion: Some("Consider adding `#[non_exhaustive]` if future variants might be added.".to_string()),
                                        references: self.references().into_iter().map(String::from).collect(),
                                        llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}

fn all_fields_pub(fields: &syn::Fields) -> bool {
    match fields {
        syn::Fields::Named(named) => named
            .named
            .iter()
            .all(|f| f.vis.to_token_stream().to_string().contains("pub")),
        syn::Fields::Unnamed(unnamed) => unnamed
            .unnamed
            .iter()
            .all(|f| f.vis.to_token_stream().to_string().contains("pub")),
        syn::Fields::Unit => true,
    }
}

fn has_non_exhaustive(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("non_exhaustive"))
}

fn find_struct_line(content: &str, ident: &syn::Ident) -> Option<u32> {
    content
        .lines()
        .position(|l| l.contains("struct") && l.contains(&ident.to_string()))
        .map(|n| n as u32 + 1)
}

fn find_enum_line(content: &str, ident: &syn::Ident) -> Option<u32> {
    content
        .lines()
        .position(|l| l.contains("enum") && l.contains(&ident.to_string()))
        .map(|n| n as u32 + 1)
}

// ---------------------------------------------------------------------------
// IdiomTemporaryMutability
// ---------------------------------------------------------------------------

/// Flag variables declared `mut` but never modified after initial assignment.
///
/// Conservative heuristic: checks if a `mut` binding has any `=` assignment
/// after its declaration line. Only scans public function bodies.
#[derive(Default)]
pub struct IdiomTemporaryMutability;

impl Rule for IdiomTemporaryMutability {
    fn id(&self) -> &'static str {
        "idiom.temporary-mutability"
    }

    fn title(&self) -> &'static str {
        "Consider removing unnecessary `mut` declarations"
    }

    fn category(&self) -> Category {
        Category::Idiom
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Detects `mut` bindings that are only assigned once, suggesting `let` instead of `let mut`."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/idioms/temporary-mutability.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Remove `mut` from bindings that are assigned only once. This clarifies intent and enables compiler optimizations.")
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
                        if !vis_str.contains("pub") {
                            continue;
                        }

                        // Find all `let mut` bindings in the function
                        let fn_content_start = content
                            .find(&format!("fn {}", fn_item.sig.ident))
                            .unwrap_or(0);
                        // Find body start
                        let body_start = content[fn_content_start..]
                            .find('{')
                            .map(|o| fn_content_start + o + 1)
                            .unwrap_or(fn_content_start);
                        let body_end = content[body_start..].find('}').map(|o| body_start + o);

                        if let Some(end) = body_end {
                            let body = &content[body_start..end];
                            let body_start_line = content[..body_start].lines().count() as u32;

                            // Look for `let mut` declarations
                            for (idx, line) in body.lines().enumerate() {
                                let trimmed = line.trim();
                                if trimmed.starts_with("let mut ")
                                    || trimmed.starts_with("let mut\t")
                                {
                                    // Extract the variable name
                                    if let Some(rest) = trimmed
                                        .strip_prefix("let mut ")
                                        .or_else(|| trimmed.strip_prefix("let mut\t"))
                                    {
                                        let var_name = rest
                                            .split(&['=', ' ', '\t', ';'][..])
                                            .next()
                                            .unwrap_or("")
                                            .to_string();
                                        if var_name.is_empty() {
                                            continue;
                                        }

                                        // Check if the variable is reassigned after this line
                                        let line_in_file = body_start_line + idx as u32;
                                        let after_decl =
                                            &content[line_in_file as usize..end.min(content.len())];
                                        let reassignment_count = after_decl
                                            .lines()
                                            .skip(1) // skip the declaration line itself
                                            .filter(|l| {
                                                let t = l.trim();
                                                // Check for reassignment patterns like `var = ` or `var.push(` etc
                                                t.contains(&format!("{var_name} ="))
                                                    || t.contains(&format!("{var_name}.push("))
                                                    || t.contains(&format!("{var_name}.clear("))
                                                    || t.contains(&format!("{var_name}.insert("))
                                                    || t.contains(&format!("{var_name}.extend("))
                                                    || t.contains(&format!("{var_name}["))
                                            })
                                            .count();

                                        if reassignment_count == 0 {
                                            out.push(Finding {
                                                rule_id: self.id().to_string(),
                                                title: self.title().to_string(),
                                                category: self.category(),
                                                severity: self.default_severity(),
                                                confidence: self.default_confidence(),
                                                location: Some(Location {
                                                    path: src_path.to_path_buf().into(),
                                                    line: Some(line_in_file),
                                                    column: None,
                                                    end_line: Some(line_in_file),
                                                    end_column: None,
                                                }),
                                                message: format!(
                                                    "`{var_name}` is declared `mut` but never reassigned; consider `let`"
                                                ),
                                                why_it_matters: "Unnecessary `mut` declarations obscure the intent that a value is constant after initialization. Removing them enables compiler optimizations and improves code readability.".to_string(),
                                                suggestion: Some(format!(
                                                    "Change `let mut {var_name}` to `let {var_name}`"
                                                )),
                                                references: self.references().into_iter().map(String::from).collect(),
                                                llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IdiomReturnConsumedArgOnError
// ---------------------------------------------------------------------------

/// Flag public functions returning `Result<T, E>` where `E` could contain
/// the consumed argument for error context.
///
/// Conservative heuristic: flags functions where the return type is
/// `Result<_, E>` and the parameter names suggest ownership transfer
/// (no `&` prefix) — suggesting the error type should capture the
/// consumed argument for debugging.
#[derive(Default)]
pub struct IdiomReturnConsumedArgOnError;

impl Rule for IdiomReturnConsumedArgOnError {
    fn id(&self) -> &'static str {
        "idiom.return-consumed-arg-on-error"
    }

    fn title(&self) -> &'static str {
        "Consider returning consumed argument in error"
    }

    fn category(&self) -> Category {
        Category::Idiom
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Suggests including consumed arguments in error variants so callers can debug failures with context about what was attempted."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/anti-patterns/clippy/return_self_not_must_use.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Include consumed arguments in error variants so that error messages provide context about what was attempted.")
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
                        if !vis_str.contains("pub") {
                            continue;
                        }

                        // Skip standard library constructors
                        let fn_name = fn_item.sig.ident.to_string();
                        if matches!(
                            fn_name.as_str(),
                            "Ok" | "Err" | "Some" | "None" | "Default" | "new"
                        ) {
                            continue;
                        }

                        // Check if return type is Result<_, _>
                        let is_result = match &fn_item.sig.output {
                            syn::ReturnType::Type(_, ty) => {
                                if let syn::Type::Path(type_path) = ty.as_ref() {
                                    type_path
                                        .path
                                        .segments
                                        .last()
                                        .map(|s| s.ident == "Result")
                                        .unwrap_or(false)
                                } else {
                                    false
                                }
                            }
                            syn::ReturnType::Default => false,
                        };

                        if !is_result {
                            continue;
                        }

                        // Check if there are owned (non-reference) parameters
                        let has_owned_args = fn_item.sig.inputs.iter().any(|arg| {
                            if let syn::FnArg::Typed(pat_type) = arg {
                                let ty_str = pat_type.ty.to_token_stream().to_string();
                                // Skip if it's a reference type
                                !ty_str.starts_with("&") && !ty_str.starts_with("& mut")
                            } else {
                                false
                            }
                        });

                        if has_owned_args {
                            let fn_name = fn_item.sig.ident.to_string();
                            let line = content
                                .lines()
                                .position(|l| l.contains("fn") && l.contains(&fn_name))
                                .map(|n| n as u32 + 1)
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
                                    "Function `{fn_name}` returns `Result` with owned arguments; consider including consumed args in error variants for better error context"
                                ),
                                why_it_matters: "When a function consumes arguments and can fail, including the consumed values in the error type helps callers debug what went wrong without re-running the function.".to_string(),
                                suggestion: Some("Add consumed argument types to the error enum so that `Err(e)` includes context about what was attempted.".to_string()),
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
// IdiomMemTakeReplace
// ---------------------------------------------------------------------------

/// Suggest `mem::take` / `mem::replace` / `Option::take` instead of `.clone()`
/// when only a default/empty value is needed temporarily.
#[derive(Default)]
pub struct IdiomMemTakeReplace;

impl Rule for IdiomMemTakeReplace {
    fn id(&self) -> &'static str {
        "idiom.mem-take-replace"
    }

    fn title(&self) -> &'static str {
        "Use mem::take / mem::replace instead of clone for temporary ownership"
    }

    fn category(&self) -> Category {
        Category::Idiom
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Detects `.clone()` followed by `.clear()` or similar patterns that could use `mem::take` / `mem::replace` / `Option::take` for zero-copy ownership transfer."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://doc.rust-lang.org/std/mem/fn.take.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Replace `.clone()` followed by `.clear()` with `std::mem::take(&mut value)` for zero-copy ownership transfer.")
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                let content = std::fs::read_to_string(src_path)?;

                // Pattern 1: `let x = value.clone(); value.clear();` (two lines)
                // We look for clone + clear within a few lines of each other
                let lines: Vec<&str> = content.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    let trimmed = line.trim();
                    // Look for clone on a variable
                    if let Some(clone_match) = trimmed.strip_prefix("let ") {
                        if clone_match.contains(".clone()") {
                            // Extract variable being cloned
                            if let Some((var_part, _)) = clone_match.split_once(" = ") {
                                let _var_name = var_part
                                    .split(&[':', ' ', '\t'][..])
                                    .next()
                                    .unwrap_or("")
                                    .to_string();
                                let clone_pos = clone_match.find(".clone()").unwrap_or(0);
                                // Extract the source variable from the clone expression
                                let source_expr =
                                    clone_match[clone_pos..].trim_end_matches(".clone()");
                                // source_expr might be `value`, `self.value`, etc.
                                let source_var = source_expr
                                    .split('.')
                                    .next_back()
                                    .unwrap_or("")
                                    .trim()
                                    .to_string();

                                // Check next few lines for .clear() on the same variable
                                let check_end = (i + 5).min(lines.len());
                                for j in (i + 1)..check_end {
                                    let next_line = lines[j].trim();
                                    if next_line.contains(&format!("{source_var}.clear()"))
                                        || next_line.contains(&format!("{source_var}.drain(.."))
                                    {
                                        let find_line = lines[..i]
                                            .iter()
                                            .position(|l| {
                                                l.contains(&format!("{source_var}.clone()"))
                                            })
                                            .map(|n| n as u32 + 1)
                                            .unwrap_or((i + 1) as u32);

                                        out.push(Finding {
                                            rule_id: self.id().to_string(),
                                            title: self.title().to_string(),
                                            category: self.category(),
                                            severity: self.default_severity(),
                                            confidence: self.default_confidence(),
                                            location: Some(Location {
                                                path: src_path.to_path_buf().into(),
                                                line: Some(find_line),
                                                column: None,
                                                end_line: Some(find_line),
                                                end_column: None,
                                            }),
                                            message: format!(
                                                "`.clone()` followed by `.clear()` on `{source_var}` can be replaced with `std::mem::take(&mut {source_var})`"
                                            ),
                                            why_it_matters: "Cloning then clearing allocates memory unnecessarily. `mem::take` swaps in a default value and returns the original, achieving the same effect with zero additional allocations.".to_string(),
                                            suggestion: Some(format!(
                                                "Replace `let x = {source_var}.clone(); {source_var}.clear();` with `let x = std::mem::take(&mut {source_var});`"
                                            )),
                                            references: self.references().into_iter().map(String::from).collect(),
                                            llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
