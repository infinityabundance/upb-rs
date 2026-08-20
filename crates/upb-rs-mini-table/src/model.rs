//! The mini table model, mirroring `struct upb_MiniTable` and
//! `struct upb_MiniTableField` (upb/mini_table/internal/message.h:71-94,
//! upb/mini_table/internal/field.h:21-35).

/// Field mode (upb/mini_table/internal/field.h:40-44).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FieldMode {
    Map = 0,
    Array = 1,
    Scalar = 2,
}

/// Field representation (upb/mini_table/internal/field.h:62-71).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FieldRep {
    OneByte = 0,
    FourByte = 1,
    StringView = 2,
    EightByte = 3,
}

/// Extra mode flags (upb/mini_table/internal/field.h:50-59).
pub const LABEL_FLAG_PACKED: u8 = 4;
pub const LABEL_FLAG_EXTENSION: u8 = 8;
pub const LABEL_FLAG_ALTERNATE: u8 = 16;

/// `kUpb_NoSub` (field.h:37) — no submessage/enum sub.
pub const NO_SUB: u16 = u16::MAX;
/// `kUpb_SubmsgOffsetBytes` (field.h:38).
pub const SUBMSG_OFFSET_BYTES: u32 = 4;

/// A field in the mini table, with the exact byte-level fields of
/// `struct upb_MiniTableField` (12 bytes on both platforms).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiniTableField {
    pub number: u32,
    pub offset: u16,
    /// >0: hasbit index; <0: ~oneof case offset; 0: none.
    pub presence: i16,
    pub submsg_ofs: u16,
    /// `descriptortype` — an `upb_FieldType` value (1..=18).
    pub descriptortype: u8,
    /// `mode` — `FieldMode | LabelFlags | (FieldRep << 6)`.
    pub mode: u8,
}

impl MiniTableField {
    pub fn mode_class(&self) -> FieldMode {
        match self.mode & 0x3 {
            0 => FieldMode::Map,
            1 => FieldMode::Array,
            _ => FieldMode::Scalar,
        }
    }

    pub fn rep(&self) -> FieldRep {
        match self.mode >> 6 {
            0 => FieldRep::OneByte,
            1 => FieldRep::FourByte,
            2 => FieldRep::StringView,
            _ => FieldRep::EightByte,
        }
    }

    pub fn is_packed(&self) -> bool {
        self.mode & LABEL_FLAG_PACKED != 0
    }

    pub fn is_alternate(&self) -> bool {
        self.mode & LABEL_FLAG_ALTERNATE != 0
    }

    pub fn is_in_oneof(&self) -> bool {
        self.presence < 0
    }

    /// `upb_MiniTableField_Type`: resolves alternates (open enum -> Enum,
    /// unvalidated string -> String).
    pub fn field_type(&self) -> u8 {
        if self.is_alternate() {
            if self.descriptortype == 5 {
                return 14; // kUpb_FieldType_Enum
            }
            if self.descriptortype == 12 {
                return 9; // kUpb_FieldType_String
            }
        }
        self.descriptortype
    }
}

/// Ext mode (upb/mini_table/internal/message.h:41-55).
pub const EXT_NON_EXTENDABLE: u8 = 0;
pub const EXT_EXTENDABLE: u8 = 1;
pub const EXT_MESSAGE_SET: u8 = 2;
pub const EXT_MAP_ENTRY: u8 = 4;

/// The built mini table (`struct upb_MiniTable`, message.h:71-94), projected
/// to the observable fields. `table_mask`/fasttable entries are excluded:
/// they are a performance artifact with no observable decode semantics (the
/// decoder falls back to the generic path), see forensics/PERFORMANCE_MODEL.md.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiniTable {
    pub size: u16,
    pub field_count: u16,
    pub ext: u8,
    pub dense_below: u8,
    pub required_count: u8,
    pub fields: Vec<MiniTableField>,
}
