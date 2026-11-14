# Retained changed-block index

Closed incremental COW files identify origin blocks changed after earlier snapshots. Parsing validates header/version, geometry, UUID/sequence, clean state and bounds. Dirty/incompatible files cannot establish a base.

Independent fixed-width decoding validates table spans, mapping values and block counts before allocation/traversal. Empty indexes and supported layouts have explicit fixtures.

Compact history groups sixteen 4 KiB mappings into one 64 KiB bit. Planning unions validated maps from exact base to current generation, coalescing overlaps and preserving coverage. Bounded queries read the current origin's index; output follows required 128-entry boundaries.

Maps establish inheritance, not NAS ownership/source health. [Planning](incremental-plan.md) also validates base, snapshot and geometry. Pending jobs/exact bases protect history from pruning; retired files may be removed while ancestry remains.
