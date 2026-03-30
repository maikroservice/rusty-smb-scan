use crate::{error::Result, scanner::HostResult};

pub fn render(results: &[HostResult]) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(vec![]);

    // Header
    wtr.write_record(["host", "share", "type", "comment", "access"])
        .map_err(|e| crate::error::SmbError::Backend(e.to_string()))?;

    for result in results {
        for share in &result.shares {
            wtr.write_record([
                &result.host,
                &share.name,
                share_type_str(&share.share_type),
                &share.comment,
                share.access.display(),
            ])
            .map_err(|e| crate::error::SmbError::Backend(e.to_string()))?;
        }
    }

    let data = wtr
        .into_inner()
        .map_err(|e| crate::error::SmbError::Backend(e.to_string()))?;

    String::from_utf8(data).map_err(|e| crate::error::SmbError::Backend(e.to_string()))
}

fn share_type_str(t: &crate::share::ShareType) -> &'static str {
    use crate::share::ShareType::*;
    match t {
        Disk => "disk",
        Printer => "printer",
        Device => "device",
        Ipc => "ipc",
        Unknown => "unknown",
    }
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
            comment: "a comment".into(),
            access,
        }
    }

    #[test]
    fn csv_has_header_row() {
        let csv = render(&[]).unwrap();
        let first_line = csv.lines().next().unwrap();
        assert!(first_line.contains("host"), "{first_line}");
        assert!(first_line.contains("share"), "{first_line}");
        assert!(first_line.contains("access"), "{first_line}");
    }

    #[test]
    fn csv_header_has_five_fields() {
        let csv = render(&[]).unwrap();
        let first_line = csv.lines().next().unwrap();
        assert_eq!(first_line.split(',').count(), 5, "header: {first_line}");
    }

    #[test]
    fn csv_data_row_has_five_fields() {
        let share = make_share("srv", "public", AccessLevel::READ);
        let csv = render(&[make_result("srv", vec![share])]).unwrap();
        let data_line = csv.lines().nth(1).unwrap();
        assert_eq!(data_line.split(',').count(), 5, "data row: {data_line}");
    }

    #[test]
    fn csv_contains_host_and_share_name() {
        let share = make_share("myserver", "documents", AccessLevel::READ);
        let csv = render(&[make_result("myserver", vec![share])]).unwrap();
        assert!(csv.contains("myserver"), "{csv}");
        assert!(csv.contains("documents"), "{csv}");
    }

    #[test]
    fn csv_contains_access_level() {
        let share = make_share("s", "rw", AccessLevel::READ | AccessLevel::WRITE);
        let csv = render(&[make_result("s", vec![share])]).unwrap();
        assert!(csv.contains("read,write"), "{csv}");
    }

    #[test]
    fn csv_two_hosts_has_header_plus_two_data_rows() {
        let results = vec![
            make_result("h1", vec![make_share("h1", "s1", AccessLevel::READ)]),
            make_result("h2", vec![make_share("h2", "s2", AccessLevel::empty())]),
        ];
        let csv = render(&results).unwrap();
        let line_count = csv.lines().count();
        assert_eq!(line_count, 3, "header + 2 rows; got: {csv}");
    }

    #[test]
    fn csv_no_shares_only_header() {
        let csv = render(&[make_result("host", vec![])]).unwrap();
        assert_eq!(csv.lines().count(), 1, "only header row; got: {csv}");
    }

    #[test]
    fn csv_comment_with_comma_is_quoted() {
        let mut share = make_share("srv", "misc", AccessLevel::empty());
        share.comment = "hello, world".into();
        let csv = render(&[make_result("srv", vec![share])]).unwrap();
        // The csv crate should quote the field; the raw comma should not
        // appear unquoted between other fields.
        assert!(csv.contains("\"hello, world\""), "{csv}");
    }
}
