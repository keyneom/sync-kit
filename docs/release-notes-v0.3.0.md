# sync-kit 0.3.0

Cross-platform profile ownership transfer for Web and Android.

- Adds a dual-signed proposal, recipient acceptance, and resumable finalization
  flow across every profile dataset.
- Transfers Google Drive authority for the app-root and exchange folders as
  well as dataset files.
- Retains the former owner as an admin by default and enables the provider
  permissions needed for that role to continue managing sharing.
- Preserves owner trust, conditional writes, participant grants, codecs, and
  encryption identity across the handoff.
- Adds shared behavioral fixtures and a frozen Web-generated transfer envelope
  verified and decrypted by Kotlin.

The built-in Google Drive flow supports consumer-account `pendingOwner`
acceptance. Google Workspace direct ownership transfer is not included.
