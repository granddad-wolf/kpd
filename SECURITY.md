# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities. Report them
privately:

- via GitHub Security Advisories on the private repository, or
- to the maintainer(s) listed in the private repo's contact file.

We aim to acknowledge within 72 hours and to fix confirmed issues promptly.
Please include a minimal reproduction and the affected version/commit.

## Security model (summary)

`kpd` is a password manager. The full threat model is maintained in
`THREAT-MODEL.md` (in the private agent repository). High-level guarantees:

- The **master key** never leaves the process and is zeroized on drop/lock.
- **Clipboard copies auto-clear**, and only if the clipboard still holds the
  exact text we wrote (never clobbering something copied later).
- **Plugins** run in a WASM sandbox with **no filesystem/network by default**,
  are capability-gated, and never receive secrets or the master key.
- **Saves are guarded**: `.bak` backup + in-memory round-trip verification +
  atomic replace, with a pre-save warning about lossy fields.

## Supported versions

No stable release yet (pre-alpha). Until `1.0`, security fixes target the
`main` branch only.

## Known limitations

See the threat model for details. Highlights:

- Saves write **KDBX 4.1 only**; KDB/KDBX3/KDBX4.0 are read-only.
- Re-saving re-serializes from the in-memory model, so un-modeled vendor XML
  (e.g. KeePassXC `<PreviousParentGroup>`) may be dropped.
- The upstream `keepass` crate does not zeroize some intermediate buffers on the
  open/save paths (upstream issue #391); `kpd` zeroizes everything it owns.
- Secrets are not yet memory-locked (`mlock`) nor protected by `MemoryProtection`.
