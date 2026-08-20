//! A Rust model of `upb_Map` (`upb/message/map.c` + `upb/message/internal/map.h`
//! at the pinned commit) — the **content semantics**.
//!
//! A map has a key size and a value size (`0` = string, `UPB_MAPTYPE_STRING`);
//! `upb_Map_Insert` is last-wins for duplicate keys (the replaced entry's
//! value is returned); `upb_Map_Get` returns the value for a key; `Delete`
//! removes it. Iteration order is the upstream table's hash order — an
//! implementation detail (the table layout, growth, and arena footprint are
//! representation; the court compares iteration as a sorted set, see
//! forensics/NONDETERMINISM.md). The DUT keeps entries in insertion order
//! with a lookup table for the observable semantics.
//!
//! Size table (`upb/message/map.c:30-42`): Bool 1; Float/Int32/UInt32/Enum 4;
//! Message/Double/Int64/UInt64 8; String/Bytes 0 (string-typed).

/// `_upb_Map_CTypeSize` (map.c:30-42): the storage size for a map key/value
/// of the given `upb_CType`; 0 = string (UPB_MAPTYPE_STRING).
pub fn ctype_map_size(ctype: u8) -> Option<u8> {
    match ctype {
        1 => Some(1),       // Bool
        2..=5 => Some(4),   // Float, Int32, UInt32, Enum
        6..=9 => Some(8),   // Message, Double, Int64, UInt64
        10 | 11 => Some(0), // String, Bytes
        _ => None,
    }
}

/// `upb_MapInsertStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapInsertStatus {
    Inserted,
    Replaced,
    OutOfMemory,
}

/// An entry: key and value bytes (string-typed entries store the raw bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A map with the observable upb_Map semantics.
#[derive(Debug, Clone)]
pub struct Map {
    /// `key_size` / `val_size`: 0 = string.
    pub key_size: u8,
    pub val_size: u8,
    entries: Vec<MapEntry>,
    index: std::collections::HashMap<Vec<u8>, usize>,
}

impl Map {
    /// `upb_Map_New(arena, key_type, value_type)` — the arena parameter only
    /// matters for the table's internal storage (representation); the DUT
    /// model keeps entries in owned storage.
    pub fn new(key_type: u8, val_type: u8) -> Option<Map> {
        Some(Map {
            key_size: ctype_map_size(key_type)?,
            val_size: ctype_map_size(val_type)?,
            entries: Vec::new(),
            index: std::collections::HashMap::new(),
        })
    }

    /// `upb_Map_Size`.
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// `upb_Map_Insert`: last-wins; a replaced entry's old value is returned
    /// (upstream reports it through the `val` out-parameter; the oracle op
    /// captures the status only).
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> MapInsertStatus {
        if let Some(&i) = self.index.get(key) {
            self.entries[i].value = value.to_vec();
            MapInsertStatus::Replaced
        } else {
            self.index.insert(key.to_vec(), self.entries.len());
            self.entries.push(MapEntry {
                key: key.to_vec(),
                value: value.to_vec(),
            });
            MapInsertStatus::Inserted
        }
    }

    /// `upb_Map_Get`: the value for `key`, if present.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.index
            .get(key)
            .map(|&i| self.entries[i].value.as_slice())
    }

    /// `upb_Map_Delete`.
    pub fn delete(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let i = self.index.remove(key)?;
        let entry = self.entries.remove(i);
        // Fix up indices after the removal.
        for (k, v) in self.index.iter_mut() {
            if *v > i {
                *v -= 1;
            }
            let _ = k;
        }
        Some(entry.value)
    }

    /// Iteration: insertion order in the DUT (the upstream order is the
    /// table's hash order — representation; courts compare sorted).
    pub fn iter(&self) -> impl Iterator<Item = &MapEntry> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_last_wins() {
        let mut m = Map::new(4, 4).unwrap(); // uint32 key/value
        assert_eq!(
            m.insert(&1u32.to_le_bytes(), &10u32.to_le_bytes()),
            MapInsertStatus::Inserted
        );
        assert_eq!(
            m.insert(&1u32.to_le_bytes(), &20u32.to_le_bytes()),
            MapInsertStatus::Replaced
        );
        assert_eq!(m.size(), 1);
        assert_eq!(m.get(&1u32.to_le_bytes()), Some(&20u32.to_le_bytes()[..]));
    }

    #[test]
    fn delete_removes_and_reindexes() {
        let mut m = Map::new(4, 4).unwrap();
        m.insert(&1u32.to_le_bytes(), &10u32.to_le_bytes());
        m.insert(&2u32.to_le_bytes(), &20u32.to_le_bytes());
        m.insert(&3u32.to_le_bytes(), &30u32.to_le_bytes());
        assert_eq!(
            m.delete(&2u32.to_le_bytes()),
            Some(20u32.to_le_bytes().to_vec())
        );
        assert_eq!(m.size(), 2);
        assert_eq!(m.get(&3u32.to_le_bytes()), Some(&30u32.to_le_bytes()[..]));
        assert_eq!(m.get(&1u32.to_le_bytes()), Some(&10u32.to_le_bytes()[..]));
    }

    #[test]
    fn string_keys() {
        let mut m = Map::new(10, 10).unwrap(); // string key/value (size 0)
        assert_eq!(m.key_size, 0);
        m.insert(b"hello", b"world");
        m.insert(b"hello", b"upb");
        assert_eq!(m.get(b"hello"), Some(&b"upb"[..]));
        assert_eq!(m.size(), 1);
    }
}
