//! JSON and SARIF output rendering.

use crate::diagnostic::{Report, Severity};

// ---------------------------------------------------------------------------
// Report → JSON (serialises the Report struct directly)
// ---------------------------------------------------------------------------

/// Render a report as pretty-printed JSON matching the Report/Finding model.
pub fn render_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Report → SARIF 2.1.0
// ---------------------------------------------------------------------------

/// Render a report as SARIF 2.1.0 JSON.
pub fn render_sarif(report: &Report) -> String {
    let mut sarif = serde_json::Map::new();
    sarif.insert(
        "version".to_string(),
        serde_json::Value::String("2.1.0".to_string()),
    );
    sarif.insert(
        "$schema".to_string(),
        serde_json::Value::String(
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
                .to_string(),
        ),
    );

    let runs: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "note",
            };

            let mut result = serde_json::Map::new();
            result.insert(
                "ruleId".to_string(),
                serde_json::Value::String(f.rule_id.clone()),
            );
            result.insert(
                "level".to_string(),
                serde_json::Value::String(level.to_string()),
            );
            result.insert(
                "message".to_string(),
                serde_json::Value::Object(serde_json::Map::from_iter([(
                    "text".to_string(),
                    serde_json::Value::String(f.message.clone()),
                )])),
            );

            if let Some(ref loc) = f.location {
                let mut region = serde_json::Map::new();
                region.insert(
                    "startLine".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(
                        loc.line.unwrap_or(0) as i64
                    )),
                );
                region.insert(
                    "startColumn".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(
                        loc.column.unwrap_or(0) as i64
                    )),
                );
                if let Some(el) = loc.end_line {
                    region.insert(
                        "endLine".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(el as i64)),
                    );
                }
                if let Some(ec) = loc.end_column {
                    region.insert(
                        "endColumn".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(ec as i64)),
                    );
                }

                let mut artifact_loc = serde_json::Map::new();
                artifact_loc.insert(
                    "uri".to_string(),
                    serde_json::Value::String(loc.path.to_string_lossy().to_string()),
                );

                let mut physical_loc = serde_json::Map::new();
                physical_loc.insert(
                    "artifactLocation".to_string(),
                    serde_json::Value::Object(artifact_loc),
                );
                physical_loc.insert("region".to_string(), serde_json::Value::Object(region));

                let mut location = serde_json::Map::new();
                location.insert(
                    "physicalLocation".to_string(),
                    serde_json::Value::Object(physical_loc),
                );

                result.insert(
                    "locations".to_string(),
                    serde_json::Value::Array(vec![serde_json::Value::Object(location)]),
                );
            }

            // Attach rule help text when available.
            if let Some(ref prompt) = f.llm_fix_prompt {
                result.insert(
                    "help".to_string(),
                    serde_json::Value::Object(serde_json::Map::from_iter([(
                        "text".to_string(),
                        serde_json::Value::String(prompt.clone()),
                    )])),
                );
            }

            serde_json::Value::Object(result)
        })
        .collect();

    let mut run = serde_json::Map::new();
    run.insert(
        "tool".to_string(),
        serde_json::Value::Object(serde_json::Map::from_iter([(
            "driver".to_string(),
            serde_json::Value::Object(serde_json::Map::from_iter([
                (
                    "name".to_string(),
                    serde_json::Value::String("rust-doctor".to_string()),
                ),
                (
                    "version".to_string(),
                    serde_json::Value::String(report.tool_version.clone()),
                ),
                (
                    "rules".to_string(),
                    serde_json::Value::Array(
                        report
                            .findings
                            .iter()
                            .map(|f| {
                                let mut rule = serde_json::Map::new();
                                rule.insert(
                                    "id".to_string(),
                                    serde_json::Value::String(f.rule_id.clone()),
                                );
                                serde_json::Value::Object(rule)
                            })
                            .collect::<Vec<_>>(),
                    ),
                ),
            ])),
        )])),
    );
    run.insert("results".to_string(), serde_json::Value::Array(runs));

    sarif.insert(
        "runs".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::Object(run)]),
    );

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}
