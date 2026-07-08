//! Anti-pattern rules: deny-warnings and deref-polymorphism.

use crate::diagnostic::{Category, Confidence, Finding, Location, Severity};
use crate::rules::registry::{Rule, RuleContext};
use quote::ToTokens;

// ---------------------------------------------------------------------------
// AntiDenyWarnings
// ---------------------------------------------------------------------------

/// Flag `#![deny(warnings)]` and `[lints] warnings = "deny"`.
#[derive(Default)]
pub struct AntiDenyWarnings;

impl Rule for AntiDenyWarnings {
    fn id(&self) -> &'static str {
        "anti.deny-warnings"
    }

    fn title(&self) -> &'static str {
        "Deny-warnings suppresses future lints"
    }

    fn category(&self) -> Category {
        Category::AntiPattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Detects `#![deny(warnings)]` crate attributes and `[lints] warnings = \"deny\"` manifest tables."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/anti-patterns/deny-warnings.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some(
            "Remove `#![deny(warnings)]` from the crate root. \
             Instead, use `RUSTFLAGS=-D warnings` in CI or explicitly deny \
             specific lint names.",
        )
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                for kind in &target.kind {
                    if kind == "lib" || kind == "bin" {
                        let src_path = target.src_path.as_path();
                        if src_path.exists() {
                            let content = std::fs::read_to_string(src_path)?;
                            if let Some((line_num, _)) = content
                                .lines()
                                .enumerate()
                                .find(|(_, l)| l.contains("#![deny(warnings)]"))
                            {
                                out.push(Finding {
                                    rule_id: self.id().to_string(),
                                    title: self.title().to_string(),
                                    category: self.category(),
                                    severity: self.default_severity(),
                                    confidence: self.default_confidence(),
                                    location: Some(Location {
                                        path: src_path.to_path_buf().into(),
                                        line: Some((line_num + 1) as u32),
                                        column: None,
                                        end_line: Some((line_num + 1) as u32),
                                        end_column: None,
                                    }),
                                    message: format!(
                                        "Package \"{}\" uses `#![deny(warnings)]` which suppresses future lints",
                                        pkg.name
                                    ),
                                    why_it_matters: "Denying all warnings opts out of Rust stability guarantees; new lints in future toolchain releases will silently pass instead of alerting you.".to_string(),
                                    suggestion: Some("Use `RUSTFLAGS=-D warnings` in CI instead, or explicitly deny specific lint names.".to_string()),
                                    references: self.references().into_iter().map(String::from).collect(),
                                    llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                                });
                            }
                        }
                    }
                }
            }
        }

        for (pkg_id, content) in &ctx.manifests {
            if let Some(pos) = content
                .lines()
                .position(|l| l.contains("warnings") && l.contains("deny"))
            {
                let manifest_path = ctx.workspace_root.join("Cargo.toml");
                out.push(Finding {
                    rule_id: self.id().to_string(),
                    title: self.title().to_string(),
                    category: self.category(),
                    severity: self.default_severity(),
                    confidence: Confidence::High,
                    location: Some(Location {
                        path: manifest_path,
                        line: Some((pos + 1) as u32),
                        column: None,
                        end_line: Some((pos + 1) as u32),
                        end_column: None,
                    }),
                    message: format!("Package \"{}\" has `[lints] warnings = \"deny\"`", pkg_id),
                    why_it_matters:
                        "Same risk as `#![deny(warnings)]`: future lints will be silently ignored."
                            .to_string(),
                    suggestion: Some(
                        "Use `RUSTFLAGS=-D warnings` in CI or explicitly deny specific lint names."
                            .to_string(),
                    ),
                    references: self.references().into_iter().map(String::from).collect(),
                    llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                });
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AntiDerefPolymorphism
// ---------------------------------------------------------------------------

/// Flag `impl Deref` targeting owned non-pointer/domain fields.
#[derive(Default)]
pub struct AntiDerefPolymorphism;

impl Rule for AntiDerefPolymorphism {
    fn id(&self) -> &'static str {
        "anti.deref-polymorphism"
    }

    fn title(&self) -> &'static str {
        "Suspicious Deref implementation"
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
        "Detects `impl Deref` that targets an owned non-pointer/domain field, which can surprise readers and interact badly with trait bounds."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/anti-patterns/deref-polymorphism.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some(
            "Instead of implementing `Deref` to another domain struct, \
             consider using composition with explicit method calls, \
             or if this is a smart-pointer or collection wrapper, \
             the `Deref` is likely appropriate.",
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
                let file: syn::File = match syn::parse_file(&content) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                for item in &file.items {
                    if let syn::Item::Impl(imp) = item {
                        if let Some((_, path, _)) = &imp.trait_ {
                            if path
                                .segments
                                .last()
                                .map(|s| s.ident == "Deref")
                                .unwrap_or(false)
                            {
                                let self_type = type_name(imp.self_ty.as_ref());
                                let target_type = extract_deref_target(imp);

                                if let Some(target) = target_type {
                                    if !is_allowlisted(&self_type, &target) {
                                        let line = find_item_line(&content, imp);
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
                                                "{} implements `Deref` to `{}` which may be deref polymorphism",
                                                self_type, target
                                            ),
                                            why_it_matters: "Deref polymorphism can surprise readers who expect subtyping semantics. It interacts badly with trait bounds and differs from OO self semantics.".to_string(),
                                            suggestion: Some(format!(
                                                "Consider if `Deref` is truly appropriate here. If `{}` is a domain type, prefer explicit method calls. If this is a smart-pointer or collection wrapper, the `Deref` is likely fine.",
                                                target
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
        Ok(())
    }
}

/// Extract the deref target type from `impl Deref for T { fn deref(...) -> &Target }`.
fn extract_deref_target(imp: &syn::ItemImpl) -> Option<String> {
    for item in &imp.items {
        if let syn::ImplItem::Fn(m) = item {
            if m.sig.ident == "deref" {
                if let syn::ReturnType::Type(_, ty) = &m.sig.output {
                    return extract_type_name(ty.as_ref());
                }
            }
        }
    }
    None
}

/// Extract a type name from a `syn::Type`.
fn extract_type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Reference(r) => extract_type_name(r.elem.as_ref()),
        syn::Type::Path(p) => type_name_syn_path(p),
        syn::Type::Slice(s) => Some(format!(
            "[{}]",
            extract_type_name(&s.elem).unwrap_or_default()
        )),
        _ => None,
    }
}

fn type_name_syn_path(p: &syn::TypePath) -> Option<String> {
    p.path.segments.last().map(|s| s.ident.to_string())
}

fn type_name(ty: &syn::Type) -> String {
    extract_type_name(ty).unwrap_or_else(|| "<unknown>".to_string())
}

/// Find the line number of an impl block in the source code.
fn find_item_line(content: &str, imp: &syn::ItemImpl) -> Option<u32> {
    let target = imp.self_ty.to_token_stream().to_string();
    content
        .lines()
        .position(|l| l.contains("impl") && l.contains(&target))
        .map(|n| (n + 1) as u32)
}

/// Check if the Deref implementation is allowlisted.
fn is_allowlisted(type_name: &str, target_name: &str) -> bool {
    let smart_pointers = ["Box", "Rc", "Arc", "Pin"];
    if smart_pointers
        .iter()
        .any(|n| type_name == *n || type_name.contains(n))
    {
        return true;
    }

    let collections = [
        "String",
        "Vec",
        "VecDeque",
        "LinkedList",
        "BTreeMap",
        "HashMap",
        "HashSet",
        "BTreeSet",
    ];
    if collections
        .iter()
        .any(|n| type_name == *n || type_name.contains(n))
    {
        return true;
    }

    let others = ["Cow", "Bytes", "PathBuf", "OsString"];
    if others
        .iter()
        .any(|n| type_name == *n || type_name.contains(n))
    {
        return true;
    }

    if target_name == "str" || (target_name.starts_with('[') && target_name.ends_with(']')) {
        return true;
    }

    let patterns = [
        "List",
        "Collection",
        "Bag",
        "Stack",
        "Queue",
        "Deque",
        "Buffer",
        "Array",
    ];
    if patterns.iter().any(|k| type_name.contains(k)) {
        return true;
    }

    false
}
