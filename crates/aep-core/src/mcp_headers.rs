pub use crate::evidence::McpHeaderRisk;

/// Check MCP-Method and MCP-Name header values for sensitive-data leakage patterns.
///
/// Returns the highest-severity risk detected, or None if no risk is found.
pub fn classify_mcp_headers(
    mcp_method: Option<&str>,
    mcp_name: Option<&str>,
) -> Option<McpHeaderRisk> {
    const CREDENTIAL_PREFIXES: &[&str] = &["ghp_", "ghb_", "sk-", "Bearer ", "token ", "api_"];
    const MIN_HIGH_ENTROPY_LEN: usize = 32;

    for val in [mcp_method, mcp_name].into_iter().flatten() {
        // Credential prefix detection (case-insensitive)
        let lower = val.to_lowercase();
        for prefix in CREDENTIAL_PREFIXES {
            if lower.starts_with(&prefix.to_lowercase() as &str) {
                return Some(McpHeaderRisk::CredentialLeak);
            }
        }
        // High-entropy detection: long alphanumeric strings
        let alnum_run: usize = val
            .split(|c: char| !c.is_alphanumeric())
            .map(|s| s.len())
            .max()
            .unwrap_or(0);
        if alnum_run >= MIN_HIGH_ENTROPY_LEN {
            return Some(McpHeaderRisk::HighEntropyValue);
        }
    }

    // PII: email pattern in MCP-Name
    if let Some(name) = mcp_name {
        if name.contains('@') && name.contains('.') {
            return Some(McpHeaderRisk::PiiLeak);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_mcp_headers_detects_credential_prefix() {
        assert_eq!(
            classify_mcp_headers(Some("ghp_abc123"), None),
            Some(McpHeaderRisk::CredentialLeak)
        );
        assert_eq!(
            classify_mcp_headers(Some("sk-abcdefghij"), None),
            Some(McpHeaderRisk::CredentialLeak)
        );
        assert_eq!(
            classify_mcp_headers(Some("Bearer token_here"), None),
            Some(McpHeaderRisk::CredentialLeak)
        );
    }

    #[test]
    fn classify_mcp_headers_detects_high_entropy() {
        let long_val = "a".repeat(40);
        assert_eq!(
            classify_mcp_headers(None, Some(&long_val)),
            Some(McpHeaderRisk::HighEntropyValue)
        );
    }

    #[test]
    fn classify_mcp_headers_detects_pii_in_name() {
        assert_eq!(
            classify_mcp_headers(None, Some("user@example.com")),
            Some(McpHeaderRisk::PiiLeak)
        );
    }

    #[test]
    fn classify_mcp_headers_clean_values_return_none() {
        assert_eq!(
            classify_mcp_headers(Some("tools/call"), Some("my_tool")),
            None
        );
        assert_eq!(classify_mcp_headers(None, None), None);
        assert_eq!(classify_mcp_headers(Some("tools/list"), None), None);
    }
}
