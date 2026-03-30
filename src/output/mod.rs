use crate::{error::SmbError, scanner::HostResult};

pub mod csv;
pub mod json;
pub mod table;

/// Supported output formats.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
}

impl std::str::FromStr for OutputFormat {
    type Err = SmbError;

    fn from_str(s: &str) -> crate::error::Result<Self> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "csv" => Ok(OutputFormat::Csv),
            other => Err(SmbError::Backend(format!(
                "unknown output format '{other}'; valid options: table, json, csv"
            ))),
        }
    }
}

/// Render `results` to a `String` in the requested format.
pub fn render(results: &[HostResult], format: &OutputFormat) -> crate::error::Result<String> {
    match format {
        OutputFormat::Table => table::render(results),
        OutputFormat::Json => json::render(results),
        OutputFormat::Csv => csv::render(results),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_table() {
        assert_eq!(OutputFormat::from_str("table").unwrap(), OutputFormat::Table);
        assert_eq!(OutputFormat::from_str("TABLE").unwrap(), OutputFormat::Table);
    }

    #[test]
    fn parse_json() {
        assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);
    }

    #[test]
    fn parse_csv() {
        assert_eq!(OutputFormat::from_str("csv").unwrap(), OutputFormat::Csv);
    }

    #[test]
    fn parse_unknown_returns_error() {
        let err = OutputFormat::from_str("xml").unwrap_err();
        assert!(err.to_string().contains("xml"), "{err}");
        assert!(err.to_string().contains("table"), "{err}");
    }
}
