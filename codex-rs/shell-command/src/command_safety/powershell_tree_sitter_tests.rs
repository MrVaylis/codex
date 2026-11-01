use pretty_assertions::assert_eq;
use serde::Deserialize;

use super::try_parse_powershell_commands;

#[derive(Debug, Deserialize)]
struct FixtureCase {
    name: String,
    script: String,
    expected: Option<Vec<Vec<String>>>,
}

#[test]
fn lowers_compact_literal_fixture() {
    // Supported outputs were captured from the PowerShell 7 AST subprocess parser. Rare forms
    // that need additional PowerShell-specific lowering are intentionally recorded as unsupported.
    let cases: Vec<FixtureCase> =
        serde_json::from_str(include_str!("fixtures/powershell_lowering.json"))
            .expect("valid PowerShell lowering fixture");

    for case in cases {
        assert_eq!(
            try_parse_powershell_commands(&case.script),
            case.expected,
            "fixture case: {}",
            case.name
        );
    }
}

#[test]
fn rejects_requires_directives() {
    assert_eq!(
        try_parse_powershell_commands("#requires -Modules Evil\nGet-Location"),
        None
    );
}

#[test]
fn lowers_literal_call_operator_for_external_cli() {
    assert_eq!(
        try_parse_powershell_commands(
            "& 'C:\\Python\\python.exe' tools/operator-api/client.py --origin http://127.0.0.1:51104 start account --target steam-only"
        ),
        Some(vec![vec![
            "C:\\Python\\python.exe".to_string(),
            "tools/operator-api/client.py".to_string(),
            "--origin".to_string(),
            "http://127.0.0.1:51104".to_string(),
            "start".to_string(),
            "account".to_string(),
            "--target".to_string(),
            "steam-only".to_string(),
        ]])
    );
}

#[test]
fn rejects_dynamic_and_non_executable_call_targets() {
    for script in [
        "& $command --origin http://127.0.0.1:51104 start",
        "& './operator.ps1' --origin http://127.0.0.1:51104 start",
        "& 'python.exe' --origin http://127.0.0.1:51104 start; Start-Process https://example.com",
    ] {
        assert_eq!(try_parse_powershell_commands(script), None, "{script}");
    }
}
