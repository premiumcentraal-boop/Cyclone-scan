# Development signing key (PUBLIC)

`cyclone-dev.jks` (PKCS12, alias `cyclone-dev`, store and key password `cyclone-dev`) is
committed on purpose. Every development build, whether local, CI or a dev pre-release,
is signed with this one key, so:

- test installs update in place across builds
- a development verification policy can allow one stable signer:
  `412b9e05c1418d4e5e1e0f86ee21687569b4623231f951e5cf6a8e67cc469416` (also in `dev-signer.sha256`)

**The key is public, so it proves nothing about who built an APK.** Anyone can sign a
repackaged app with it. Therefore:

- `device-trust check-config --profile beta` fails, and `tools/release/check_signing.py`
  reports `DEV_KEY`, whenever a policy allows this digest
- production builds use the `CYCLONE_RELEASE_*` secrets instead, which take precedence
  when they are set (see docs/RUN_18_BETA_PACKAGING.md)

Do not reuse this key for anything else. To rotate it, replace both files in one commit.
Installed dev builds must then be uninstalled once.
