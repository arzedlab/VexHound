# Samples

This directory holds large or third-party test inputs that are not committed to
git (see `.gitignore`). Only this README is tracked. Everything here is optional:
the test suite uses the small fixtures under `tests/fixtures/` instead.

Expected layout when populated locally:

    samples/
      corpus/              cross-architecture demo binaries (vuln_*, clean_*, firm_sink_*)
      overflow_demo_bin/   controlled x86 overflow example binaries (for emulate / tests)
      firmware/            vendor firmware images (*.bin, *.zip)

## Rebuilding the demo binaries

The controlled targets are built from `tests/fixtures/src/vuln.c` cross-compiled for
each architecture. The `firm_sink_*` targets model a firmware handler that reads an
environment variable and reaches an unbounded copy / `system()`.

## Firmware images

Firmware is downloaded from the vendor and is not redistributed here. For example
the TP-Link TL-WR841N v14 image comes from the vendor support pages. Extract a
SquashFS root filesystem with binwalk before pointing VexHound at the binaries:

    binwalk -e firmware/<image>.bin

Point `vexhound emulate --engine qiling --rootfs <extracted-rootfs> ...` at the
extracted tree so the loader and shared libraries resolve.

You can override the fixture search path with `VEXHOUND_SAMPLES=/path/to/dir`.
