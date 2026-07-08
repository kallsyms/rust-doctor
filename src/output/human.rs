//! Human-readable output rendering.
//!
//! Groups findings by category, then by severity within each category.
//! Shows file locations, confidence, suggestions, references, and LLM fix prompts.

use crate::diagnostic::{Category, Confidence, Finding, Report};

/// Render a report as human-readable text.
pub fn render(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "rust-doctor v{} — {}\n\n",
        report.tool_version,
        report.workspace_root.display()
    ));

    let s = &report.summary;
    out.push_str(&format!(
        "Score: {}/100 ({} — {})\n",
        s.health.score, s.health.grade, s.health.label
    ));
    out.push_str(&format!(
        "Summary: {} total ({} errors, {} warnings, {} infos)\n\n",
        s.total, s.errors, s.warnings, s.infos
    ));

    if report.findings.is_empty() {
        out.push_str("✓ No issues found.\n");
        return out;
    }

    // Order categories in a stable, logical order.
    let category_order: &[Category] = &[
        Category::AntiPattern,
        Category::Idiom,
        Category::Organization,
        Category::Pattern,
        Category::Toolchain,
    ];

    for category in category_order {
        let label = category.label();
        let items: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| &f.category == category)
            .collect();

        if items.is_empty() {
            continue;
        }

        out.push_str(&format!("=== {label} ===\n\n"));

        // Within each category, sort by severity (errors first, then warnings, then infos),
        // then by rule_id for stability.
        let mut sorted = items;
        sorted.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        for f in &sorted {
            let loc = f.location.as_ref().map(|l| {
                // Try to display the path relative to the workspace root.
                let display_path = l
                    .path
                    .strip_prefix(&report.workspace_root)
                    .ok()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| l.path.display().to_string());
                format!(
                    "{}:{}:{}",
                    display_path,
                    l.line.unwrap_or(0),
                    l.column.unwrap_or(0)
                )
            });
            let loc_str = loc.as_deref().unwrap_or("??");
            let conf_str = confidence_label(f.confidence);
            out.push_str(&format!(
                "  [{}/{}] {} — {}\n",
                f.rule_id, conf_str, loc_str, f.message
            ));

            if !f.why_it_matters.is_empty() {
                out.push_str(&format!("    Why: {}\n", f.why_it_matters));
            }

            if let Some(ref suggestion) = f.suggestion {
                out.push_str(&format!("    → {suggestion}\n"));
            }

            if let Some(ref prompt) = f.llm_fix_prompt {
                out.push_str(&format!("    LLM: {prompt}\n"));
            }

            if !f.references.is_empty() {
                let refs: Vec<&str> = f.references.iter().map(|r| r.as_str()).collect();
                out.push_str(&format!("    Ref: {}\n", refs.join(", ")));
            }

            out.push('\n');
        }
    }

    out
}

fn confidence_label(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}
