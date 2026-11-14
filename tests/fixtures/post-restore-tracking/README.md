# Synthetic reservation recovery fixture

`synthetic-reservations.json` models prepared and ready capture ownership with synthetic boot, capture, filesystem, LVM, COW and snapshot identifiers. Equal identifiers remain equal across records; null/zero sentinels and phase relationships are preserved.

The portable reservation regression tests reject old ownership formats, adopt fresh sequence-one recovery, renew initialized owners and reject changed topology, COW identity, forged markers and invented ancestry. No device or network access is required.
