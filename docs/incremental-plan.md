# Incremental planning

Automatic machine CBT uses retained generation maps and the NAS-selected base, reading only sent intervals with small raw caches instead of hashing/comparing complete filesystem images. Raw/static intervals keep their reread rules.

Plans bind exact task, completed base version/result, capture, generation and geometry. The base must remain assigned/complete and match NAS selection. A resumed job cannot substitute another base. Initial jobs without usable history establish full backup through normal selection.

Ordered offset/length ranges cover each image. Changed ranges carry bytes; inherited ranges use `changed=0` without payload. Allocation and internal-COW exclusions independently determine `used`; a free inherited range can be `used=0, changed=0`. `is_interval_cbt` describes context independently of changed state.

Maps combine required history from base to current, including overlap and mandatory boundaries. Execution revalidates geometry, UUIDs, ancestry and health. Saved plans/compression remain immutable on resume.

`get_base_version` returns a nonnegative signed 32-bit ID; zero means no usable base. Resume checks running CBT/base metadata and uses logical checkpoint, including inherited-range positions. Transferred-byte counters never select read offsets.

The explicit single-volume provider shifts changed ranges by its 1 MiB prefix and transfers prefix/tail; its digest policy differs from automatic direct-source capture. Diagnostic workflows are outside installed CLI. See [indexes](cow-index.md), [tracking](persistent-machine-cbt.md) and [resume](backup-resume.md).
