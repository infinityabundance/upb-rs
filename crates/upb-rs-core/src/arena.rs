//! A Rust model of `upb_Arena` (`upb/mem/arena.c` + `upb/mem/internal/arena.h`
//! at the pinned commit `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`).
//!
//! This is a **semantic** model: it reproduces the observable behavior of the
//! C arena — bump allocation with exponential block growth capped at the max
//! block size, the one-off escape hatch, `SpaceAllocated` accounting, fuse
//! lifetime merging, cleanup execution at free, fixed-size and initial-block
//! modes, realloc/shrink/try-extend pointer identity, and OOM failure via an
//! injected allocator threshold — without reproducing the C address layout.
//! Pointer identity is modeled by (block index, byte offset) handles that are
//! stable for the arena's lifetime (the upstream pointer-stability guarantee,
//! forensics/MEMORY_MODEL.md §1.6).
//!
//! All block data is stored in `Box<[u64]>`, so every allocation base is
//! 8-byte aligned and blocks never move; no unsafe is required (the unsafe
//! ledger stays empty).
//!
//! The build-configuration constants that affect the accounting
//! (`ArenaConfig`) are reported by the oracle's `arena_info` op rather than
//! hardcoded, so the model tracks whatever the oracle was built with (release
//! vs ASAN builds differ in `guard_size` and `state_reserve`).

/// Build-configuration constants affecting arena behavior. These are the
/// values the pinned oracle binary was built with (see `arena_info` in
/// tools/oracle): `upb/port/def.inc` and `upb/mem/sanitizers.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArenaConfig {
    /// `UPB_MALLOC_ALIGN` — 8, or 16 under HWASAN.
    pub malloc_align: usize,
    /// `kUpb_Asan_GuardSize` — 32 under ASAN, 0 otherwise. Added to every
    /// allocation span.
    pub guard_size: usize,
    /// `kUpb_MemblockReserve` = ALIGN_MALLOC(sizeof(upb_MemBlock)) — 16 on
    /// 64-bit. Every block contributes (data_size + this) to
    /// `space_allocated`.
    pub memblock_reserve: usize,
    /// `kUpb_ArenaStateReserve` = ALIGN_MALLOC(sizeof(upb_ArenaState)) — 80 in
    /// release builds. The first block's data size and the inline-state
    /// consumption in initial-block arenas.
    pub state_reserve: usize,
    /// `UPB_DEFAULT_MAX_BLOCK_SIZE` — 32768 (8192 on Android).
    pub default_max_block_size: usize,
}

/// The default configuration for the oracle's release build.
pub const RELEASE_CONFIG: ArenaConfig = ArenaConfig {
    malloc_align: 8,
    guard_size: 0,
    memblock_reserve: 16,
    state_reserve: 80,
    default_max_block_size: 32768,
};

/// An allocation handle: (block index, byte offset) within the pool's arena.
/// This is the DUT's pointer identity; it is stable for the arena's lifetime
/// and never reused while the arena lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alloc {
    block: usize,
    offset: usize,
    size: usize,
}

impl Alloc {
    /// The requested size at allocation time (realloc/shrink/try-extend
    /// update it).
    pub fn size(&self) -> usize {
        self.size
    }

    /// Pointer identity: whether two handles denote the same address.
    pub fn same_address(&self, other: &Alloc) -> bool {
        self.block == other.block && self.offset == other.offset
    }

    /// A sub-region of an allocation (e.g. the array's element data inside
    /// the struct allocation).
    pub(crate) fn sub(outer: Alloc, offset: usize, size: usize) -> Alloc {
        Alloc {
            block: outer.block,
            offset: outer.offset + offset,
            size,
        }
    }
}

/// A controlled exact-size allocator with OOM injection. Mirrors the oracle's
/// controlled allocator (tools/oracle `arena_*` ops): every request is
/// fulfilled exactly (no usable-size rounding, unlike glibc's
/// `malloc_usable_size`), and once the cumulative requested bytes would
/// exceed `fail_after` (0 = never), allocation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlledAllocator {
    total: u64,
    fail_after: u64,
}

impl ControlledAllocator {
    pub fn new(fail_after: u64) -> ControlledAllocator {
        ControlledAllocator {
            total: 0,
            fail_after,
        }
    }

    /// Attempts to take `size` bytes; returns false when the injected failure
    /// threshold is exceeded.
    fn take(&mut self, size: u64) -> bool {
        if self.fail_after != 0 && self.total + size > self.fail_after {
            return false;
        }
        self.total += size;
        true
    }
}

/// One arena block: 8-aligned storage with its data size (the size the arena
/// bump-allocates from; the memblock header is modeled in the accounting, not
/// stored).
#[derive(Debug)]
struct Block {
    data_size: usize,
    _data: Box<[u64]>,
}

/// A live arena in the pool.
#[derive(Debug)]
struct ArenaState {
    has_initial_block: bool,
    has_alloc: bool,
    /// Blocks added via `_upb_Arena_AddBlock`, in order.
    blocks: Vec<Block>,
    /// The current bump region: block index + ptr offset (None = no region).
    bump: Option<(usize, usize)>,
    /// `end` of the bump region (relative to the bump block's start).
    end: usize,
    last_block_size: u32,
    size_hint: u32,
    /// This arena's own block total (`space_allocated` member).
    space_allocated: u64,
    /// The arena's alloc cleanup id (`upb_alloc_cleanup`), if set.
    cleanup: Option<u64>,
    /// Union-find parent; a root points to itself.
    parent: usize,
    /// Root-only: live-handle count of the fuse group.
    count: u64,
    /// Root-only: the fused list (root first, then fused arenas in fuse
    /// order). Mirrors the upstream singly-linked `next` list; upstream's
    /// list order depends on the lower-address root selection, which is
    /// representation (the court compares cleanup sets, not order, for fused
    /// groups — forensics/NONDETERMINISM.md).
    members: Vec<usize>,
    freed: bool,
}

impl ArenaState {
    fn has(&self) -> usize {
        match self.bump {
            // The initial-block virtual region (no backing block) is bounded
            // by `end` alone.
            Some((usize::MAX, p)) => self.end.saturating_sub(p),
            Some((b, p)) => self.blocks[b].data_size.saturating_sub(p),
            None => 0,
        }
    }
}

/// A pool of arenas with index handles. One pool owns one global
/// `max_block_size` (upstream's process-global `g_max_block_size`) and one
/// controlled allocator (the oracle drives one arena at a time; the court
/// creates a fresh pool per case).
#[derive(Debug)]
pub struct ArenaPool {
    cfg: ArenaConfig,
    max_block_size: usize,
    alloc: ControlledAllocator,
    arenas: Vec<ArenaState>,
}

impl ArenaPool {
    pub fn new(cfg: ArenaConfig, alloc: ControlledAllocator) -> ArenaPool {
        ArenaPool {
            cfg,
            max_block_size: cfg.default_max_block_size,
            alloc,
            arenas: Vec::new(),
        }
    }

    pub fn set_max_block_size(&mut self, max: usize) {
        self.max_block_size = max;
    }

    /// `upb_Arena_Init(mem, n, alloc)`:
    /// - `initial_block = Some(n)` models a user buffer of `n` bytes (the DUT
    ///   buffer is 8-aligned; the upstream pointer is aligned up first);
    /// - `has_alloc` selects a block allocator (None -> fixed-size when an
    ///   initial block is present, NULL arena when there is no initial block);
    /// - `first_size_hint` is the `n` passed as the size hint for
    ///   `_upb_Arena_InitSlow` when no initial block is used (0 is the
    ///   `upb_Arena_New` default).
    pub fn new_arena(
        &mut self,
        initial_block: Option<usize>,
        has_alloc: bool,
        first_size_hint: usize,
    ) -> Option<usize> {
        match initial_block {
            Some(n) => {
                // The user buffer is 8-aligned in the DUT; upstream aligns it
                // up and reduces n by the delta (0 here).
                if n < self.cfg.state_reserve {
                    // `_upb_Arena_InitSlow(alloc, mem ? 0 : n)`.
                    return self.init_slow(has_alloc, 0);
                }
                let idx = self.push_state(true, has_alloc);
                let a = &mut self.arenas[idx];
                // State is placed at the buffer start; the bump region starts
                // at ALIGN_MALLOC(state + 1) == state_reserve and extends to n.
                // growth state starts at 128/128 (arena.c:585-586). The
                // initial block is NOT an upb_MemBlock: it is not counted in
                // space_allocated and not in the blocks list.
                a.bump = Some((usize::MAX, self.cfg.state_reserve));
                a.end = n;
                a.last_block_size = 128;
                a.size_hint = 128;
                a.space_allocated = 0;
                Some(idx)
            }
            None => self.init_slow(has_alloc, first_size_hint),
        }
    }

    fn push_state(&mut self, has_initial_block: bool, has_alloc: bool) -> usize {
        let idx = self.arenas.len();
        self.arenas.push(ArenaState {
            has_initial_block,
            has_alloc,
            blocks: Vec::new(),
            bump: None,
            end: 0,
            last_block_size: 0,
            size_hint: 0,
            space_allocated: 0,
            cleanup: None,
            parent: idx,
            count: 1,
            members: vec![idx],
            freed: false,
        });
        idx
    }

    /// `_upb_Arena_InitSlow`: malloc the first block, place the state inside
    /// it. Returns None when there is no allocator or the allocator fails.
    fn init_slow(&mut self, has_alloc: bool, first_size: usize) -> Option<usize> {
        if !has_alloc {
            return None;
        }
        let data_size = self.cfg.state_reserve
            + self
                .cfg
                .malloc_align
                .max(self.align_up(first_size) + self.cfg.guard_size)
                .max(256);
        let idx = self.push_state(false, true);
        let block = self.alloc_block(idx, data_size)?;
        // last_block_size / size_hint are seeded with the first block's data
        // size (arena.c:528-529), before the state reserve is subtracted.
        let a = &mut self.arenas[idx];
        a.last_block_size = block_size_u32(data_size, a);
        a.size_hint = a.last_block_size;
        a.space_allocated = data_size as u64 + self.cfg.memblock_reserve as u64;
        a.blocks[block].data_size = data_size;
        a.bump = Some((block, self.cfg.state_reserve));
        a.end = data_size;
        Some(idx)
    }

    /// `upb_Arena_Malloc`: fast path when the current bump region fits the
    /// span, else `_upb_Arena_SlowMalloc`. Returns None on allocation
    /// failure.
    pub fn malloc(&mut self, a: usize, size: usize) -> Option<Alloc> {
        let span = self.span(size);
        if self.arenas[a].has() >= span {
            let (b, p) = self.arenas[a].bump?;
            self.arenas[a].bump = Some((b, p + span));
            return Some(Alloc {
                block: b,
                offset: p,
                size,
            });
        }
        self.slow_malloc(a, span, size)
    }

    fn span(&self, size: usize) -> usize {
        self.align_up(size) + self.cfg.guard_size
    }

    fn align_up(&self, x: usize) -> usize {
        (x + self.cfg.malloc_align - 1) & !(self.cfg.malloc_align - 1)
    }

    /// Allocates a block of at least `data_size` usable bytes (exact, with
    /// the controlled allocator) from the pool allocator, records the
    /// `space_allocated` contribution, and returns the block index.
    fn alloc_block(&mut self, a: usize, data_size: usize) -> Option<usize> {
        let requested = data_size + self.cfg.memblock_reserve;
        if !self.alloc.take(requested as u64) {
            return None;
        }
        let len_u64 = data_size.div_ceil(8);
        let block = Block {
            data_size,
            _data: vec![0u64; len_u64].into_boxed_slice(),
        };
        self.arenas[a].blocks.push(block);
        Some(self.arenas[a].blocks.len() - 1)
    }

    /// `_upb_Arena_SlowMalloc` (arena.c:480-509).
    fn slow_malloc(&mut self, a: usize, span: usize, requested: usize) -> Option<Alloc> {
        if !self.arenas[a].has_alloc {
            return None;
        }
        let mut one_off = false;
        let block_size = self.next_block_size(a, span, &mut one_off);
        let block = self.alloc_block(a, block_size)?;
        // With the controlled allocator the actual data size equals the
        // requested block size.
        self.arenas[a].space_allocated += block_size as u64 + self.cfg.memblock_reserve as u64;
        self.arenas[a].blocks[block].data_size = block_size;

        let size = span - self.cfg.guard_size;
        // Recheck the one-off decision with the actual block size
        // (arena.c:495-499).
        if one_off && !self.would_reduce_free_space(a, span, block_size) {
            one_off = false;
        }
        self.update_growth_state(a, span, block_size, one_off);

        if one_off {
            // The whole block is returned as one allocation.
            return Some(Alloc {
                block,
                offset: 0,
                size: requested,
            });
        }
        self.use_block(a, block, block_size);
        // Re-enter the fast path with `size`; guaranteed to fit.
        let (b, p) = self.arenas[a].bump?;
        let s2 = self.span(size);
        debug_assert!(self.arenas[a].end - p >= s2);
        self.arenas[a].bump = Some((b, p + s2));
        Some(Alloc {
            block: b,
            offset: p,
            size: requested,
        })
    }

    /// `_upb_Arena_NextBlockSize` (arena.c:437-462).
    fn next_block_size(&self, a: usize, span: usize, one_off: &mut bool) -> usize {
        let max = self.max_block_size;
        let mut block_size = (self.arenas[a].last_block_size as usize * 2).min(max);
        if span > block_size {
            block_size = (self.arenas[a].size_hint as usize * 2).min(max);
            if span > block_size {
                *one_off = true;
            }
        }
        if self.would_reduce_free_space(a, span, block_size) {
            *one_off = true;
        }
        if *one_off {
            block_size = span;
        }
        block_size
    }

    /// `_upb_Arena_WouldReduceFreeSpace` (arena.c:428-435): a one-off block is
    /// preferred when the current block's remaining space is at least the new
    /// block's would-be leftover. Note `block_size - span` is unsigned
    /// **wrapping** in C (a huge value when the block is smaller than the
    /// span), so the comparison is false in that case — mirrored here.
    fn would_reduce_free_space(&self, a: usize, span: usize, block_size: usize) -> bool {
        let current_free = if self.arenas[a].blocks.is_empty() {
            0
        } else {
            self.arenas[a].has()
        };
        let future_free = block_size.wrapping_sub(span);
        current_free >= future_free
    }

    /// `_upb_Arena_UpdateGrowthState` (arena.c:464-476).
    fn update_growth_state(&mut self, a: usize, span: usize, block_size: usize, one_off: bool) {
        let max = self.max_block_size;
        let st = &mut self.arenas[a];
        if one_off {
            st.size_hint = (st.size_hint as usize + (span >> 1)).min(max >> 1) as u32;
        } else {
            st.last_block_size = block_size.min(u32::MAX as usize) as u32;
            st.size_hint = st.last_block_size;
        }
    }

    /// `_upb_Arena_UseBlock` (arena.c:407-417): the new block becomes the bump
    /// region only when larger than the current remaining space.
    fn use_block(&mut self, a: usize, block: usize, size: usize) {
        if size <= self.arenas[a].has() {
            return;
        }
        self.arenas[a].bump = Some((block, 0));
        self.arenas[a].end = size;
    }

    /// `upb_Arena_Realloc` (internal/arena.h:141-170): in-place when shrinking
    /// or when `TryExtend` succeeds; otherwise a fresh allocation.
    pub fn realloc(&mut self, a: usize, mut ptr: Alloc, new_size: usize) -> Option<Alloc> {
        if new_size <= ptr.size || self.try_extend(a, &mut ptr, new_size) {
            if new_size <= ptr.size && self.was_last_alloc(a, ptr, ptr.size) {
                self.shrink_last(a, &mut ptr, new_size);
            }
            ptr.size = new_size;
            Some(ptr)
        } else {
            self.malloc(a, new_size)
        }
    }

    /// `upb_Arena_ShrinkLast` (internal/arena.h:101-120). Updates `ptr`'s size
    /// (upstream records the new size in its side table; the handle is the
    /// DUT's equivalent).
    pub fn shrink_last(&mut self, a: usize, ptr: &mut Alloc, new_size: usize) {
        if self.was_last_alloc(a, *ptr, ptr.size) {
            if let Some((b, _p)) = self.arenas[a].bump {
                // `a->ptr -= align(oldsize) - align(size)`: ptr_old ==
                // offset + span(oldsize), so new ptr == offset + span(size).
                self.arenas[a].bump = Some((b, ptr.offset + self.span(new_size)));
                ptr.size = new_size;
            }
        }
    }

    /// `upb_Arena_TryExtend` (internal/arena.h:123-139). On success updates
    /// `ptr`'s size (upstream updates its side table).
    pub fn try_extend(&mut self, a: usize, ptr: &mut Alloc, new_size: usize) -> bool {
        let extend = self.span(new_size).saturating_sub(self.span(ptr.size));
        if self.was_last_alloc(a, *ptr, ptr.size) && self.arenas[a].has() >= extend {
            if let Some((b, p)) = self.arenas[a].bump {
                self.arenas[a].bump = Some((b, p + extend));
                ptr.size = new_size;
                return true;
            }
        }
        false
    }

    /// `_upb_Arena_WasLastAllocFromCurrentBlock`: ptr + span(size) == a->ptr.
    fn was_last_alloc(&self, a: usize, ptr: Alloc, size: usize) -> bool {
        match self.arenas[a].bump {
            Some((b, p)) => ptr.block == b && ptr.offset + self.span(size) == p,
            None => false,
        }
    }

    /// `upb_Arena_SetAllocCleanup`: sets the arena's alloc cleanup id (one per
    /// arena, run at free after its blocks are freed).
    pub fn set_cleanup(&mut self, a: usize, id: u64) {
        self.arenas[a].cleanup = Some(id);
    }

    fn find_root(&mut self, mut a: usize) -> usize {
        // Path-compressed union-find (upstream's `_upb_Arena_FindRoot` with
        // lazy collapsing).
        let mut path = Vec::new();
        while self.arenas[a].parent != a {
            path.push(a);
            a = self.arenas[a].parent;
        }
        for n in path {
            self.arenas[n].parent = a;
        }
        a
    }

    fn find_root_immut(&self, mut a: usize) -> usize {
        while self.arenas[a].parent != a {
            a = self.arenas[a].parent;
        }
        a
    }

    /// `upb_Arena_Fuse` (arena.c:878-906): merges the lifetimes of two arena
    /// groups. Refuses arenas with initial blocks. The DUT always fuses into
    /// the first group's root; upstream fuses into the lower-address root,
    /// which is representation (see NONDETERMINISM.md — the fused cleanup
    /// ORDER is not compared by the court).
    pub fn fuse(&mut self, a: usize, b: usize) -> bool {
        if self.arenas[a].has_initial_block || self.arenas[b].has_initial_block {
            return false;
        }
        let ra = self.find_root(a);
        let rb = self.find_root(b);
        if ra == rb {
            return true;
        }
        // Absorb rb into ra: refcounts add; rb's list appends to ra's.
        let b_count = self.arenas[rb].count;
        self.arenas[ra].count += b_count;
        let b_members = std::mem::take(&mut self.arenas[rb].members);
        self.arenas[ra].members.extend(b_members);
        self.arenas[rb].parent = ra;
        true
    }

    /// `upb_Arena_IsFused`.
    pub fn is_fused(&self, a: usize, b: usize) -> bool {
        self.find_root_immut(a) == self.find_root_immut(b)
    }

    /// `upb_Arena_SpaceAllocated(a, &fused_count)`: the sum over the fuse
    /// group's blocks, and the group's arena count.
    pub fn space_allocated(&self, a: usize) -> (u64, usize) {
        let root = self.find_root_immut(a);
        let mut total = 0u64;
        let mut count = 0usize;
        for &m in &self.arenas[root].members {
            total += self.arenas[m].space_allocated;
            count += 1;
        }
        (total, count)
    }

    /// `upb_Arena_Free`: decrements the group refcount; the group is
    /// destroyed when the count reaches 1. Returns the alloc-cleanup ids that
    /// ran, in fused-list order (the order is deterministic for a single
    /// arena; for fused groups it depends on upstream's address-based root
    /// selection and is compared as a set by the court). Only registered
    /// cleanups are reported (the oracle records nothing for arenas without
    /// one).
    pub fn free(&mut self, a: usize) -> Vec<u64> {
        let root = self.find_root(a);
        if self.arenas[root].count > 1 {
            self.arenas[root].count -= 1;
            self.arenas[a].freed = true;
            return Vec::new();
        }
        // Refcount == 1: destroy the group (`_upb_Arena_DoFree`).
        let members = self.arenas[root].members.clone();
        let mut cleanups = Vec::new();
        for m in members {
            if let Some(c) = self.arenas[m].cleanup {
                cleanups.push(c);
            }
            self.arenas[m].freed = true;
        }
        cleanups
    }

    /// `upb_Arena_Malloc` of `table_size` zeroed bytes — `_upb_Message_New`
    /// (message/internal/message.h:296-310). Returns the allocation.
    pub fn message_new(&mut self, a: usize, table_size: usize) -> Option<Alloc> {
        self.malloc(a, table_size)
    }
}

fn block_size_u32(data_size: usize, _a: &ArenaState) -> u32 {
    data_size.min(u32::MAX as usize) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> ArenaPool {
        ArenaPool::new(RELEASE_CONFIG, ControlledAllocator::new(0))
    }

    #[test]
    fn fast_path_bumps_within_block() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        let x = p.malloc(a, 8).unwrap();
        let y = p.malloc(a, 8).unwrap();
        assert!(x.same_address(&x));
        assert!(!x.same_address(&y));
        // The bump region starts at state_reserve (80); offsets 80 and 88 in
        // block 0, both 8-aligned.
        assert_eq!((x.block, x.offset), (0, 80));
        assert_eq!((y.block, y.offset), (0, 88));
        let (space, count) = p.space_allocated(a);
        // first block = 80 + max(256, 0) = 336 data; +16 reserve
        assert_eq!(space, 352);
        assert_eq!(count, 1);
    }

    #[test]
    fn growth_doubles_until_max() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        // Exhaust the first block (336 bytes) with aligned allocs of 8.
        for i in 0..44 {
            assert!(p.malloc(a, 8).is_some(), "alloc {i} failed");
        }
        // Next alloc triggers a second block: 2 * 336 = 672 data (+16 reserve).
        let (space, _) = p.space_allocated(a);
        assert_eq!(space, 352 + 688);
    }

    #[test]
    fn fixed_size_arena_fails_when_exhausted() {
        let mut p = pool();
        // initial block of 160 bytes, no allocator -> fixed size
        let a = p.new_arena(Some(160), false, 0).unwrap();
        let x = p.malloc(a, 8).unwrap();
        // bump region is [state_reserve=80, 160): 80 bytes -> 10 allocs of 8
        for i in 0..9 {
            assert!(p.malloc(a, 8).is_some(), "alloc {i} failed");
        }
        assert!(p.malloc(a, 8).is_none());
        let _ = x;
    }

    #[test]
    fn no_alloc_and_no_initial_block_fails() {
        let mut p = pool();
        assert!(p.new_arena(None, false, 0).is_none());
    }

    #[test]
    fn oom_injection_fails_allocs() {
        let mut p = ArenaPool::new(RELEASE_CONFIG, ControlledAllocator::new(352));
        let a = p.new_arena(None, true, 0).unwrap();
        // First block (336 + 16 = 352) fits exactly under the threshold.
        assert!(p.malloc(a, 8).is_some());
        // Exhaust the block; the next block request (672 + 16 = 688) would
        // push the total over 352 -> NULL.
        for _ in 0..40 {
            p.malloc(a, 8);
        }
        assert!(p.malloc(a, 8).is_none());
    }

    #[test]
    fn realloc_in_place_when_last() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        let x = p.malloc(a, 16).unwrap();
        // Extend the last alloc in place: 16 -> 24 (aligned spans 16 and 24).
        let same = p.realloc(a, x, 24).unwrap();
        assert!(same.same_address(&x));
        assert_eq!(same.size(), 24);
        // Shrink in place.
        let s = p.realloc(a, same, 8).unwrap();
        assert!(s.same_address(&x));
        assert_eq!(s.size(), 8);
    }

    #[test]
    fn realloc_copies_when_not_last() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        let x = p.malloc(a, 16).unwrap();
        let y = p.malloc(a, 8).unwrap();
        // x is not the last alloc; realloc must move.
        let r = p.realloc(a, x, 32).unwrap();
        assert!(!r.same_address(&x));
        let _ = y;
    }

    #[test]
    fn try_extend_fails_for_non_last() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        let mut x = p.malloc(a, 16).unwrap();
        let mut y = p.malloc(a, 8).unwrap();
        assert!(!p.try_extend(a, &mut x, 32));
        // Last alloc extends in place.
        assert!(p.try_extend(a, &mut y, 16));
    }

    #[test]
    fn one_off_block_for_huge_alloc() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        // A 70000-byte alloc exceeds 2 * max_block_size (32768) -> one-off.
        let _x = p.malloc(a, 70000).unwrap();
        let (space, _) = p.space_allocated(a);
        // first block 352 + one-off block (70000 data + 16 reserve)
        assert_eq!(space, 352 + 70016);
    }

    #[test]
    fn cleanup_runs_on_free() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        p.set_cleanup(a, 7);
        p.malloc(a, 8);
        let cleanups = p.free(a);
        assert_eq!(cleanups, vec![7]);
    }

    #[test]
    fn fuse_shares_lifetime_and_accounting() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        let b = p.new_arena(None, true, 0).unwrap();
        p.malloc(a, 8);
        assert!(p.fuse(a, b));
        assert!(p.is_fused(a, b));
        p.malloc(b, 8);
        let (space, count) = p.space_allocated(a);
        assert_eq!(count, 2);
        assert_eq!(space, 352 * 2);
        // Freeing a leaves the group alive (b's allocation is still valid);
        // freeing b destroys it. Fast-path allocs add no block space.
        assert!(p.free(a).is_empty());
        assert!(p.malloc(b, 8).is_some());
        let (space, _) = p.space_allocated(b);
        assert_eq!(space, 352 * 2);
        assert!(p.free(b).is_empty());
    }

    #[test]
    fn fuse_refuses_initial_block_arenas() {
        let mut p = pool();
        let a = p.new_arena(None, true, 0).unwrap();
        let b = p.new_arena(Some(200), true, 0).unwrap();
        assert!(!p.fuse(a, b));
        assert!(!p.is_fused(a, b));
    }

    #[test]
    fn max_block_size_caps_growth() {
        let mut p = pool();
        p.set_max_block_size(1024);
        let a = p.new_arena(None, true, 0).unwrap();
        // Exhaust the first block (336 data: 4 allocs of 64 from offset 80),
        // then 672 (10 allocs), then growth doubles but caps at 1024 (16
        // allocs per block). 100 allocs of 64 -> blocks 336, 672, 1024 x6.
        for _ in 0..100 {
            p.malloc(a, 64);
        }
        let (space, _) = p.space_allocated(a);
        // data: 336 + 672 + 1024*6 = 7152; reserve: 8 blocks * 16 = 128
        assert_eq!(space, 7152 + 128);
    }
}
