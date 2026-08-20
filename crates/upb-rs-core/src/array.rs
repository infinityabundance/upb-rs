//! A Rust model of `upb_Array` (`upb/message/array.c` +
//! `upb/message/internal/array.h` at the pinned commit).
//!
//! The array is a single arena allocation holding the struct header and the
//! element data: `bytes = ALIGN_UP(sizeof(upb_Array), 8) + (capacity << lg2)`
//! (internal/array.h:79-98); growth is capacity doubling from
//! `max(capacity, 4)` through `upb_Arena_Realloc` of the data region
//! (array.c:163-189), which is in-place exactly when the data region is the
//! arena's last allocation — observable through the arena's
//! `SpaceAllocated` accounting. The DUT mirrors both the content semantics
//! (size, element bytes) and the arena footprint (via the `ArenaPool` handles).
//!
//! Element sizes come from the `upb_CType` table
//! (`mini_table/internal/size_log2.h:25-38`): Bool 1 byte; Float/Int32/
//! UInt32/Enum 4; Message/Double/Int64/UInt64 8; String/Bytes 16 (a
//! `upb_StringView`).

use crate::arena::{Alloc, ArenaPool};

/// `_upb_CType_SizeLg2` (mini_table/internal/size_log2.h:25-38).
pub fn ctype_lg2(ctype: u8) -> Option<usize> {
    match ctype {
        1 => Some(0),       // Bool
        2..=5 => Some(2),   // Float, Int32, UInt32, Enum
        6..=9 => Some(3),   // Message, Double, Int64, UInt64
        10 | 11 => Some(4), // String, Bytes
        _ => None,
    }
}

/// `ALIGN_UP(sizeof(struct upb_Array), UPB_MALLOC_ALIGN)` = 24 (64-bit).
const ARRAY_HEADER: usize = 24;
/// `_UPB_ARRAY_DEFAULT_INITIAL_SIZE`.
const DEFAULT_INITIAL_CAPACITY: usize = 4;

/// An arena-backed repeated-field array.
#[derive(Debug, Clone)]
pub struct Array {
    /// Arena handle for the array's allocation (header + initial data).
    _array_alloc: Alloc,
    /// Arena handle for the element data region (capacity << lg2 bytes).
    data: Alloc,
    /// log2 of the element size.
    lg2: usize,
    /// The number of elements.
    size: usize,
    /// Allocated storage, measured in elements.
    capacity: usize,
    /// The element bytes (semantic content; the arena handles track the
    /// footprint).
    content: Vec<u8>,
}

impl Array {
    pub fn lg2(&self) -> usize {
        self.lg2
    }
    pub fn size(&self) -> usize {
        self.size
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    /// The element bytes as a slice.
    pub fn data(&self) -> &[u8] {
        &self.content[..self.size << self.lg2]
    }
    pub fn get(&self, i: usize) -> Option<&[u8]> {
        if i >= self.size {
            return None;
        }
        let esz = 1usize << self.lg2;
        Some(&self.content[i * esz..(i + 1) * esz])
    }
}

impl ArenaPool {
    /// `upb_Array_New(arena, ctype)`: one arena allocation of
    /// `ARRAY_HEADER + 4 << lg2` bytes; the data region starts at the header.
    pub fn array_new(&mut self, arena: usize, lg2: usize) -> Option<Array> {
        let bytes = ARRAY_HEADER + (DEFAULT_INITIAL_CAPACITY << lg2);
        let array_alloc = self.malloc(arena, bytes)?;
        let data = Alloc::sub(array_alloc, ARRAY_HEADER, DEFAULT_INITIAL_CAPACITY << lg2);
        Some(Array {
            _array_alloc: array_alloc,
            data,
            lg2,
            size: 0,
            capacity: DEFAULT_INITIAL_CAPACITY,
            content: vec![0u8; DEFAULT_INITIAL_CAPACITY << lg2],
        })
    }

    /// `_upb_Array_Realloc` (array.c:163-189): capacity doubling from
    /// `max(capacity, 4)` until >= `min_capacity`, reallocating the data
    /// region through the arena.
    pub fn array_reserve(&mut self, arena: usize, arr: &mut Array, min_capacity: usize) -> bool {
        if arr.capacity >= min_capacity {
            return true;
        }
        let mut new_capacity = arr.capacity.max(DEFAULT_INITIAL_CAPACITY);
        while new_capacity < min_capacity {
            match new_capacity.checked_mul(2) {
                Some(c) => new_capacity = c,
                None => {
                    new_capacity = usize::MAX;
                    break;
                }
            }
        }
        if new_capacity == usize::MAX {
            return false; // overflow: no valid array can hold SIZE_MAX elements
        }
        let new_bytes = match new_capacity.checked_shl(arr.lg2 as u32) {
            Some(b) => b,
            None => return false,
        };
        // The data handle carries the old size; realloc is in-place when the
        // data region is the arena's last allocation.
        let data = match self.realloc(arena, arr.data, new_bytes) {
            Some(d) => d,
            None => return false,
        };
        arr.data = data;
        arr.content.resize(new_bytes, 0);
        arr.capacity = new_capacity;
        true
    }

    /// `_upb_Array_ResizeUninitialized`-equivalent: grows the capacity when
    /// needed and sets the element count.
    pub fn array_resize(&mut self, arena: usize, arr: &mut Array, new_size: usize) -> bool {
        if new_size > arr.capacity && !self.array_reserve(arena, arr, new_size) {
            return false;
        }
        arr.size = new_size;
        true
    }

    /// `upb_Array_Append`: appends one element's bytes.
    pub fn array_append(&mut self, arena: usize, arr: &mut Array, bytes: &[u8]) -> bool {
        let esz = 1usize << arr.lg2;
        if bytes.len() != esz {
            return false;
        }
        if !self.array_resize(arena, arr, arr.size + 1) {
            return false;
        }
        // The element just appended is at index size-1 (size was incremented
        // by the resize).
        let idx = arr.size - 1;
        arr.content[idx * esz..(idx + 1) * esz].copy_from_slice(bytes);
        true
    }

    /// `upb_Array_Set` (array.c:80-85): overwrites element `i`. Upstream does
    /// not bounds-check against `size` (its `UPB_ASSERT(i < size)` is compiled
    /// out under NDEBUG) — a write at `size <= i < capacity` lands in the
    /// uninitialized-but-allocated region and only becomes visible through the
    /// data hex after the array grows past `i`; the oracle's data dump prints
    /// `size` elements, so such writes are invisible until then. A write at
    /// `i >= capacity` would overflow the heap allocation — C UB; the DUT
    /// refuses it instead (documented divergence, §49: a memory-safety
    /// vulnerability is not a compatibility requirement).
    pub fn array_set(&mut self, arr: &mut Array, i: usize, bytes: &[u8]) -> bool {
        let esz = 1usize << arr.lg2;
        if bytes.len() != esz || i >= arr.capacity {
            return false;
        }
        arr.content[i * esz..(i + 1) * esz].copy_from_slice(bytes);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::{ArenaPool, ControlledAllocator, RELEASE_CONFIG};

    fn pool() -> ArenaPool {
        ArenaPool::new(RELEASE_CONFIG, ControlledAllocator::new(0))
    }

    #[test]
    fn new_allocates_header_plus_initial_data() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        let arr = p.array_new(a, 2).unwrap(); // 4-byte elements
        assert_eq!(arr.size(), 0);
        assert_eq!(arr.capacity(), 4);
        // bytes = 24 + 4<<2 = 40, aligned 40; fast path in the first block.
        let (space, _) = p.space_allocated(a);
        assert_eq!(space, 352);
    }

    #[test]
    fn append_grows_capacity_by_doubling() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        let mut arr = p.array_new(a, 2).unwrap();
        for i in 0..8u32 {
            assert!(p.array_append(a, &mut arr, &i.to_le_bytes()));
        }
        assert_eq!(arr.size(), 8);
        // 5th append: capacity 4 -> 8, data 16 -> 32 bytes (in-place realloc).
        // 9th would double to 16.
        assert_eq!(arr.capacity(), 8);
        assert_eq!(arr.get(7), Some(&7u32.to_le_bytes()[..]));
    }

    #[test]
    fn ctype_sizes() {
        assert_eq!(ctype_lg2(1), Some(0)); // Bool
        assert_eq!(ctype_lg2(2), Some(2)); // Float
        assert_eq!(ctype_lg2(6), Some(3)); // Message
        assert_eq!(ctype_lg2(10), Some(4)); // String
        assert_eq!(ctype_lg2(0), None);
    }
}
