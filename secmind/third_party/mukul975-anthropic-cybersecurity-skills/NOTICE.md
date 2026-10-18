# Anthropic-Cybersecurity-Skills attribution

SecMind includes a metadata-only, modified selection catalog derived from
`mukul975/Anthropic-Cybersecurity-Skills` at commit
`673da1f3b0b7be34ffc9624ef3858fe45f1c3bed`.

- Upstream: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
- License: Apache License 2.0 (see `LICENSE` in this directory)
- Selection: 273 of 817 `SKILL.md` files, statically reviewed by the
  project-owner-provided fusion analysis
- Modifications: SecMind vendors only normalized metadata, descriptions,
  provenance hashes, risk labels, and deterministic capability hints. It does
  not vendor or execute upstream scripts, assets, references, or command bodies.
- Source locks: `selection-manifest.json` SHA-256
  `ae76a954490f31e8bafb8dd7f5c8376e1b6bab12e7f5596dc9d9c2fa71c2d1e3`;
  `selected-skills.csv` SHA-256
  `b0b02b216657ed0f8f3df9bedeb8fd330ab868dc64bfed8dd6ac8ca74500e9d2`.

Every vendored card retains its upstream relative path and SHA-256 in
`src/secmind/external_skill_catalog.json`. External cards are untrusted L5
advisory data; only SecMind-signed L4 packages may become executable skills.
