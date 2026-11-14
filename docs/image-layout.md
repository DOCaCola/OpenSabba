# Image layout inspection

The reader operates on fixed regular images with explicit 512/4096-byte sectors. It reports scheme, disk identity, length, partition offsets/lengths, MBR types/boot flags and GPT identities/attributes without mounting or inferring sector size.

Primary MBR and GPT are supported. Both GPT headers/arrays must pass checksums, agree on identities/geometry, stay within usable space and have nonoverlapping extents. Arrays are bounded to 16 MiB. Inclusive ending LBAs become byte offset/length pairs; GUIDs use standard text byte order. Extended/hybrid layouts are rejected and damaged images are not repaired.

Geometry alone is not backup metadata. Filesystem identity, mounts, LVM and allocation come from capture layers; inspection results must not directly become `upload_backup_spec`.

Portable fixtures cover sector sizes, GUIDs, checksum/header conflicts, overlaps, limits and unsupported layouts. Inspection commands are in the optional diagnostic executable, outside the installed surface.
