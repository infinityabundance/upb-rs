# oneof-case-word-dump — DUT dump regression caught by decode-submsg

**Status**: FIXED (the regression is gone; this casefile is permanent
regression evidence per charter §21).
**Court**: `decode-submsg-v1` (casefile ids dsm-000074 `sm-oneof-empty`,
dsm-000080 `sm-oneof-unknown`; the historical receipts under
`receipts/decode-submsg-v1-*` retain the full residual records).
**Oracle**: protobuf `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`.
**Date**: 2026-08-20.

## What it is

The oracle's normalized dump emits a `oneof_cases` entry (the case word,
0 when no member is set) for **every** distinct oneof case offset in a
mini table, whether or not any oneof member is present. The DUT's
`Message::dump` originally collected case offsets only from *present*
fields, so an empty message with a oneof rendered `"oneof_cases":[]`
while the oracle rendered `"oneof_cases":[{"case_offset":8,"case":0}]`.

## Why it existed

The decode-known court never exercised an empty oneof message — its oneof
battery always set at least one member, so every case offset was collected
through the present-field path. The residual-first loop worked as designed:
the decode-submsg corpus's `sm-oneof-empty` case (empty payload against
`A { oneof { B b = 1; uint32 x = 2; } }`) exposed the divergence that
decode-known could not.

## When it was introduced

Introduced with the original `Message::dump` (decode-known court, first
implementation); latent until the decode-submsg corpus generated an empty
oneof message.

## What relies on it

The dump is the differential comparison surface for both message courts.
Presence-independent oneof case words are part of upb's observable state:
the case word lives in the message buffer and is readable through the
accessor API even when 0.

## What would break if "cleaned up"

Rendering oneof cases only when present would silently drop observable
state (a case word of 0 is distinct from an absent oneof), producing
residuals against the oracle for any empty-oneof payload — exactly the
dsm-000074/dsm-000080 residuals.

## Which court preserves it

- `courts/decode-submsg` (op `decode_submsg`): `sm-oneof-empty`,
  `sm-oneof-unknown`, and every other oneof payload.
- `courts/decode-known`: `dk-oneof-empty` was added to the corpus (the gap
  this casefile documents) and is sealed at 0 residuals.
- Unit test `submessage_oneof_switch_and_merge` in
  `crates/upb-rs-wire/src/message_known.rs`.

## Witness

Oracle (empty oneof message, `decode_submsg` mds `["2433295e217c23","2429"]`
links `[[1],[]]`, empty payload):

```json
{"status":"ok","dump":{"fields":[],"oneof_cases":[{"case_offset":8,"case":0}],"unknown":""}}
```

Old DUT (regression): `"oneof_cases":[]`. New DUT: identical to the oracle.

## Related discovery (oracle tooling)

The `sm-unlinked-unknown` case (dsm-000012) surfaced an oracle *tooling*
bug: the initial `run_decode_submsg` rejected a missing link entry with
`bad_links`, but upstream's contract (mini_descriptor/link.h:37-40) is that
an unlinked sub-slot decodes as an unknown field. Fixed in the oracle to
leave unlinked slots unlinked; oracle and DUT now agree (both treat the
field as unknown). Not an upstream divergence — a witness of the
differential methodology catching oracle-side defects too.
