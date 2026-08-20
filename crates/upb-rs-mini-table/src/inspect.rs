//! Normalized rendering of a mini table, used by the mini-table-inspect
//! court to compare the pinned oracle's built table with the Rust model
//! (§11 of the charter: "a decoder/inspector tool capable of rendering
//! upstream and Rust mini-table structures into normalized machine-readable
//! forms").
//!
//! The rendering is a faithful projection of `struct upb_MiniTable` and
//! `struct upb_MiniTableField`: every raw field is emitted so the court
//! compares the exact layout algorithm, not a lossy summary. Fast-table
//! entries are excluded (performance artifact, no observable semantics).

use serde_json::json;

use crate::model::*;

/// Renders the table as the normalized JSON form.
pub fn inspect(table: &MiniTable, version: Option<u8>) -> serde_json::Value {
    let fields: Vec<serde_json::Value> = table
        .fields
        .iter()
        .map(|f| {
            json!({
                "number": f.number,
                "type": f.descriptortype,
                "mode": f.mode,
                "offset": f.offset,
                "presence": f.presence,
                "submsg_ofs": f.submsg_ofs,
            })
        })
        .collect();

    // Oneof grouping: fields with presence < 0 carry the negated case offset.
    let mut oneofs: Vec<(u16, Vec<usize>)> = Vec::new();
    for (i, f) in table.fields.iter().enumerate() {
        if f.is_in_oneof() {
            let case_offset = (!f.presence) as u16;
            match oneofs.iter_mut().find(|(c, _)| *c == case_offset) {
                Some((_, members)) => members.push(i),
                None => oneofs.push((case_offset, vec![i])),
            }
        }
    }
    oneofs.sort_by_key(|(c, _)| *c);
    let oneofs: Vec<serde_json::Value> = oneofs
        .into_iter()
        .map(|(case_offset, mut members)| {
            members.sort_unstable();
            json!({ "case_offset": case_offset, "members": members })
        })
        .collect();

    json!({
        "version": version.map(|v| (v as char).to_string()),
        "size": table.size,
        "field_count": table.field_count,
        "dense_below": table.dense_below,
        "ext": table.ext,
        "required_count": table.required_count,
        "fields": fields,
        "oneofs": oneofs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::build_mini_table;

    #[test]
    fn empty_message_inspect() {
        let (mt, v) = build_mini_table(b"$").unwrap();
        let j = inspect(&mt, v);
        assert_eq!(j["size"], 8);
        assert_eq!(j["field_count"], 0);
        assert_eq!(j["oneofs"].as_array().unwrap().len(), 0);
    }
}
