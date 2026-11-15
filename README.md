# Pipi Manual Fresh updates

Public release distribution for the independent Windows x64 desktop application.
This repository contains only the release workflow, its manifest signer/validator and the public verification key. Do not commit private signing keys, backups, passwords, tokens or application data.

The signing key is held in a repository Actions secret. The workflow is manually dispatched; there is no scheduled, push or pull-request release trigger and no environment approval gate. Workflow/repository write access is therefore part of the signing trust boundary.

## Release procedure
1. Prepare a reviewed draft tagged `vMAJOR.MINOR.BUILD.REVISION`.
2. Attach exactly `PipiManualFresh-MAJOR.MINOR.BUILD.REVISION-win-x64.zip`.
3. Manually dispatch **Publish verified Pipi update** on `main`, entering that four-part version.
4. The workflow validates the ZIP and embedded version/public trust anchor, signs and verifies the manifest, rechecks the attached ZIP, then publishes the release.
5. Verify the published manifest signature and ZIP hash independently before recommending the release to users.

## Initial 0.3.0.0 testing status
Compiled and source-reviewed; offline cryptographic/archive/filesystem/runtime-primitive tests passed. Actual Windows update, restart, cancellation and rollback end-to-end behavior is not yet validated. The initial bootstrap must be installed manually because earlier versions have no updater. Later update checks happen only on the user's click.

The application is not Authenticode-signed. Manifest signing is not Windows code signing. Preserve Windows download security markings; do not bypass Windows app protections.
