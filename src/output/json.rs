use serde::Serialize;

use crate::{
    error::Result,
    scanner::HostResult,
    share::Share,
};

#[derive(Serialize)]
struct JsonOutput<'a> {
    hosts: Vec<JsonHost<'a>>,
}

#[derive(Serialize)]
struct JsonHost<'a> {
    host: &'a str,
    shares: &'a [Share],
    errors: Vec<String>,
}

pub fn render(results: &[HostResult]) -> Result<String> {
    let output = JsonOutput {
        hosts: results
            .iter()
            .map(|r| JsonHost {
                host: &r.host,
                shares: &r.shares,
                errors: r.errors.iter().map(|e| e.to_string()).collect(),
            })
            .collect(),
    };
    serde_json::to_string_pretty(&output).map_err(|e| crate::error::SmbError::Backend(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::SmbError,
        scanner::HostResult,
        share::{AccessLevel, Share, ShareType},
    };
    use pretty_assertions::assert_eq;

    fn make_result(host: &str, shares: Vec<Share>) -> HostResult {
        HostResult {
            host: host.into(),
            shares,
            errors: vec![],
        }
    }

    fn make_share(host: &str, name: &str, access: AccessLevel) -> Share {
        Share {
            host: host.into(),
            name: name.into(),
            share_type: ShareType::Disk,
            comment: "test share".into(),
            access,
        }
    }

    #[test]
    fn renders_valid_json() {
        let results = vec![make_result(
            "srv01",
            vec![make_share("srv01", "public", AccessLevel::READ)],
        )];
        let json = render(&results).unwrap();
        // Must parse without error
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(v.is_object());
    }

    #[test]
    fn json_contains_host_name() {
        let results = vec![make_result("fileserver", vec![])];
        let json = render(&results).unwrap();
        assert!(json.contains("fileserver"), "{json}");
    }

    #[test]
    fn json_contains_share_name_and_access() {
        let share = make_share("srv", "confidential", AccessLevel::READ | AccessLevel::WRITE);
        let results = vec![make_result("srv", vec![share])];
        let json = render(&results).unwrap();
        assert!(json.contains("confidential"), "{json}");
        assert!(json.contains("read,write"), "{json}");
    }

    #[test]
    fn json_round_trip_preserves_fields() {
        let share = Share {
            host: "srv01".into(),
            name: "data".into(),
            share_type: ShareType::Disk,
            comment: "Data share".into(),
            access: AccessLevel::READ,
        };
        let results = vec![make_result("srv01", vec![share])];
        let json = render(&results).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let first_share = &parsed["hosts"][0]["shares"][0];

        assert_eq!(first_share["name"], "data");
        assert_eq!(first_share["comment"], "Data share");
        assert_eq!(first_share["access"], "read");
        assert_eq!(first_share["share_type"], "disk");
    }

    #[test]
    fn json_includes_errors_as_strings() {
        let mut result = make_result("broken", vec![]);
        result.errors.push(SmbError::Backend("connection reset".into()));

        let json = render(&[result]).unwrap();
        assert!(json.contains("connection reset"), "{json}");
    }

    #[test]
    fn json_empty_results_renders_empty_hosts_array() {
        let json = render(&[]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["hosts"].as_array().unwrap().len(), 0);
    }
}
