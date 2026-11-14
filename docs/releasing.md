# Preparing a release

Release builds run natively on amd64 and arm64 inside Debian 12 containers. The complete CTest suite must pass before product-only Debian packages and Linux archives are built. A second clean Debian 12 container installs each package and checks its version and dependencies. The archives are extracted to check the product binary, documentation links, licenses and integration files.

1. Update the `project(OpenSabba VERSION ...)` value in `CMakeLists.txt` and add a nonempty `## [X.Y.Z]` section to `CHANGELOG.md`. Release notes come from that section. Keep the experimental status and deployment limitations accurate.
2. Push the changes to `main` and require CI to pass for both architectures.
3. Start a dry run from `main`:

   ```sh
   gh workflow run release.yml --ref main -f dry_run=true
   gh run list --workflow release.yml
   gh run watch RUN_ID --exit-status
   gh run download RUN_ID --name release-bundle --dir release-artifacts
   (cd release-artifacts && sha256sum --check SHA256SUMS)
   ```

   The workflow run's Artifacts section also provides `packages-amd64`, `packages-arm64` and the combined `release-bundle`. The bundle contains both `.deb` files, both `.tar.gz` archives and `SHA256SUMS`. A dry run never publishes or creates a tag. Branch dispatches are accepted only with `dry_run=true`.
4. Review the artifacts, checksums and changelog. After approval, create the annotated version tag on the tested commit and push it:

   ```sh
   git tag -a v1.0.0 -m "OpenSabba 1.0.0"
   git push origin v1.0.0
   ```

A `v*.*.*` tag push triggers a fresh release build, install checks and checksum generation, then publishes a GitHub release with the changelog notes and five release files. The tag must exactly match the CMake version. A manual dispatch with `dry_run=false` also requires that matching tag as its ref; a branch dispatch cannot publish. Only the publishing job has write permission, using `GITHUB_TOKEN`.

The product version controls CLI output, diagnostic exports and package metadata. NAS-facing agent version/build fields are separate protocol constants; do not change them as part of a product release.
