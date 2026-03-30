use tabled::{Table, Tabled};

use crate::{error::Result, scanner::HostResult};

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "Host")]
    host: String,
    #[tabled(rename = "Share")]
    share: String,
    #[tabled(rename = "Type")]
    share_type: String,
    #[tabled(rename = "Access")]
    access: String,
    #[tabled(rename = "Comment")]
    comment: String,
}

pub fn render(results: &[HostResult]) -> Result<String> {
    let rows: Vec<Row> = results
        .iter()
        .flat_map(|r| {
            r.shares.iter().map(|s| Row {
                host: r.host.clone(),
                share: s.name.clone(),
                share_type: format!("{:?}", s.share_type).to_lowercase(),
                access: s.access.display().to_string(),
                comment: s.comment.clone(),
            })
        })
        .collect();

    if rows.is_empty() {
        return Ok("No shares found.\n".into());
    }

    Ok(Table::new(rows).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        scanner::HostResult,
        share::{AccessLevel, Share, ShareType},
    };

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
            comment: "test comment".into(),
            access,
        }
    }

    #[test]
    fn table_contains_host_name() {
        let results = vec![make_result(
            "fileserver",
            vec![make_share("fileserver", "docs", AccessLevel::READ)],
        )];
        let output = render(&results).unwrap();
        assert!(output.contains("fileserver"), "{output}");
    }

    #[test]
    fn table_contains_share_name() {
        let results = vec![make_result(
            "srv",
            vec![make_share("srv", "confidential", AccessLevel::READ)],
        )];
        let output = render(&results).unwrap();
        assert!(output.contains("confidential"), "{output}");
    }

    #[test]
    fn table_contains_access_column() {
        let results = vec![make_result(
            "srv",
            vec![make_share("srv", "rw", AccessLevel::READ | AccessLevel::WRITE)],
        )];
        let output = render(&results).unwrap();
        assert!(output.contains("read,write"), "{output}");
    }

    #[test]
    fn table_has_header_row_labels() {
        let results = vec![make_result(
            "srv",
            vec![make_share("srv", "x", AccessLevel::empty())],
        )];
        let output = render(&results).unwrap();
        assert!(output.contains("Host"), "{output}");
        assert!(output.contains("Share"), "{output}");
        assert!(output.contains("Access"), "{output}");
    }

    #[test]
    fn empty_results_returns_no_shares_message() {
        let output = render(&[]).unwrap();
        assert!(output.contains("No shares"), "{output}");
    }

    #[test]
    fn multiple_shares_all_appear_in_table() {
        let results = vec![make_result(
            "srv",
            vec![
                make_share("srv", "alpha", AccessLevel::READ),
                make_share("srv", "beta", AccessLevel::READ | AccessLevel::WRITE),
                make_share("srv", "gamma", AccessLevel::empty()),
            ],
        )];
        let output = render(&results).unwrap();
        assert!(output.contains("alpha"), "{output}");
        assert!(output.contains("beta"), "{output}");
        assert!(output.contains("gamma"), "{output}");
    }
}
