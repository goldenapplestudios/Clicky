# Upstream contributions

Changes prepared against projects Clicky depends on, kept here so they aren't
lost between "we found the gap" and "upstream merged it."

## `kalilix-add-modern-recon-tools.patch`

**Target:** [scopecreep-zip/kalilix](https://github.com/scopecreep-zip/kalilix)
**Touches:** `modules/devshells/default.nix` (+13 −2)
**Prepared against:** `e526cd7`

Adds six tools to Kalilix's `#kali` devShell that are already packaged in
nixpkgs but not currently exposed:

| Tool | Why |
|---|---|
| `nuclei` | The shell has no templated vulnerability scanner at all |
| `katana` | No JS-aware crawler; static crawling cannot see SPA routes |
| `feroxbuster` | Depth for content discovery (currently ffuf/gobuster only) |
| `subfinder` | Passive subdomain discovery |
| `amass` | Attack-surface mapping |
| `netexec` | Maintained successor to the deprecated `crackmapexec` |

All six are Go/Rust/Python and cross-platform, so no `isLinux` gating is
needed — unlike `wpscan`/`volatility`/`burpsuite`, which the file already
gates. The `shellHook` category listing is extended to match the file's
existing voice.

### Verified before submitting

```
nix eval .#devShells.x86_64-linux.kali.name          # -> kalilix-kali
nix eval --json .#devShells.x86_64-linux.kali.buildInputs \
  --apply 'l: map (p: p.pname or p.name) l'          # -> all six present, 82 total
```

### To submit

```bash
git clone https://github.com/scopecreep-zip/kalilix.git
cd kalilix
git checkout -b kali-modern-recon-tools
git am < /path/to/Clicky/contrib/kalilix-add-modern-recon-tools.patch
# then push to a fork and open a PR
```

The patch is a `git format-patch` output, so `git am` preserves the commit
message and authorship. Re-attribute it with `git commit --amend --author=...`
if you'd rather it land under a different name.

### Why Clicky's own `flake.nix` still exists after this merges

It doesn't become redundant. Clicky can't depend on an unmerged PR, and
listing a tool in both places is a no-op (Nix resolves PATH first-match). As
tools land upstream they get deleted from `clickyExtraTools` in
`../flake.nix`; nothing else changes. `semgrep` and `trivy` stay Clicky-only
by design — they're SAST/SCA for the white-box source-analysis path, not
penetration-testing tools, so they're out of scope for a Kali shell.
