{
  description = "Clicky pentest toolchain: Kalilix's Kali shell plus the tools Clicky's own skills require";

  # --- Why this flake exists ------------------------------------------------
  #
  # Clicky's agents get their pentest tools from Kalilix
  # (github:scopecreep-zip/kalilix), selected via the `tool_provisioning`
  # userConfig option. Kalilix's #kali devShell provides 33 tools and covers
  # most of what Clicky invokes - ffuf, gobuster, sqlmap, nikto, hydra,
  # whatweb, nmap, smbclient, enum4linux, masscan, john, hashcat, wpscan,
  # dirb, medusa, binwalk, tcpdump and more, all verified working.
  #
  # But several tools that Clicky's scripts treat as the PRIMARY choice are
  # not in Kalilix's set, and two of them have no meaningful fallback:
  #
  #   nuclei      skills/web-vulnerability-testing/scripts/nuclei-scan.sh has
  #               no alternative path at all - without it the script emits
  #               {"tool_used":"none","status":"not_installed"} and the entire
  #               templated-vulnerability stage silently does nothing.
  #   katana      skills/web-crawling/scripts/crawl.sh's JS-aware crawler.
  #               Its fallback is a static-HTML extractor that says so
  #               outright: "static HTML extraction cannot see JS-rendered
  #               routes." On any SPA target (React/Next.js/Vue) that is the
  #               difference between finding the app's routes and not.
  #   semgrep     skills/source-code-analysis taint scanner; falls back to a
  #               bundled regex/proximity scanner, which is materially weaker.
  #   trivy       skills/source-code-analysis dependency scanner; falls back
  #               to per-ecosystem tools (npm audit, pip-audit, ...) that must
  #               each be present individually.
  #   feroxbuster fuzz.sh cascade position #2 (ffuf, which Kalilix does ship,
  #               is #1 - so this is genuine depth rather than a gap).
  #   subfinder   subdomain-enum.sh additive sources. Not fallbacks: the
  #   amass       script unions their results with crt.sh, so their absence
  #               silently narrows the discovered attack surface.
  #   netexec     the maintained successor to crackmapexec. NOTE: Clicky does
  #               not invoke this yet - skills/tool-management/scripts/
  #               tool-fallback.sh's smb_enum cascade still names the
  #               deprecated crackmapexec. Shipped here so that cascade can be
  #               updated without a second toolchain change.
  #
  # Rather than forking Kalilix or asking operators to install these by hand,
  # this composes on top of Kalilix's own exported devShell with mkShell's
  # `inputsFrom`, which propagates all the inputs from the given derivations.
  # Kalilix stays the upstream source of truth for its 33 tools; this flake
  # only adds what Clicky additionally needs.
  #
  # --- Relationship to the upstream contribution ----------------------------
  #
  # Six of these (nuclei, katana, feroxbuster, subfinder, amass, netexec) are
  # pentest-native and belong in Kalilix itself rather than here. That change
  # is prepared as a patch against Kalilix's own modules/devshells/default.nix
  # - see contrib/kalilix-add-modern-recon-tools.patch and contrib/README.md.
  #
  # This flake does NOT go away when that lands, and does not wait for it:
  #   - Clicky must work today, against released Kalilix, with no unmerged
  #     dependency. A plugin that only functions once someone else merges a PR
  #     is broken by default.
  #   - Listing a tool both here and upstream is harmless. Nix resolves PATH
  #     first-match, so a duplicate is a no-op, not a conflict. That means the
  #     upstream PR can land at any time with no coordinated change here.
  #   - As tools land upstream, delete them from `clickyExtraTools` below.
  #     Nothing else has to change. In the limit this list empties out and the
  #     flake becomes a thin pin over Kalilix, which is the intended end state.
  #
  # semgrep and trivy are deliberately NOT in the upstream patch. They are
  # SAST/SCA tooling for Clicky's white-box source-analysis path, not
  # penetration-testing tools, so they sit outside what a "Kali Security
  # Testing Environment" shell is for. They stay Clicky-specific.
  #
  # --- How Clicky consumes it -----------------------------------------------
  #
  # NOT via `nix develop`. skills/mcp-gateway/scripts/launch.sh extracts this
  # shell's PATH with `nix print-dev-env --json` and launches the gateway
  # server with it. That is deliberate and load-bearing: the MCP stdio
  # transport specification states that a server "MUST NOT write anything to
  # its stdout that is not a valid MCP message," and Kalilix's shellHook
  # prints a large ASCII banner on stdout. Entering the devShell would inject
  # that banner directly into the JSON-RPC channel and no frame would parse.
  #
  # `print-dev-env --json` serialises shellHook as *data* and never executes
  # it, so the gateway gets the tools with a provably clean stdout - correct
  # by construction rather than by suppressing output after the fact.
  #
  # (mkShell concatenates the shellHooks of everything in `inputsFrom`, so an
  # interactive `nix develop` here will still print Kalilix's banner. That is
  # fine and even desirable for a human; it never reaches the gateway path.)

  inputs = {
    # Tracks nixos-unstable deliberately. These are offensive-security tools
    # whose value degrades quickly as they age - nuclei's templates and
    # katana's crawling in particular. flake.lock pins the exact revision, so
    # this is reproducible; updating is an explicit `nix flake update`.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    kalilix.url = "github:scopecreep-zip/kalilix";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, kalilix, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          # Kalilix's own shell includes unfree packages (burpsuite); keep the
          # same posture here so composition doesn't fail on evaluation.
          config.allowUnfree = true;
        };

        # Tools Clicky's scripts invoke that Kalilix's #kali shell does not
        # provide. Every entry is referenced by a real script in this repo -
        # see the per-tool rationale in the header comment above.
        clickyExtraTools = with pkgs; [
          nuclei
          katana
          feroxbuster
          semgrep
          trivy
          subfinder
          amass
          netexec

          # --- UDP / unauthenticated-service recon ---------------------------
          # agents/recon-agent.md Phase 1 is required to cover UDP, and
          # skills/nmap-scanning's UDP step (`nmap -sU`) needs raw sockets,
          # which an unprivileged engagement shell does not have. The ordinary
          # UDP *client* tools below need no privileges at all, so they are the
          # real UDP coverage path - but none of them ship in Kalilix's #kali
          # set, and tool-fallback.sh returns `none` for every one of them.
          # That combination is the worst case this repo has a rule against:
          # a missing tool reads exactly like a negative result. Confirmed
          # absent on a live engagement host, all via the gateway.
          net-snmp      # snmpwalk/snmpget/snmpbulkwalk - SNMP is the highest
                        # value UDP probe: hrSWRunTable and the LanMan user
                        # tables expose local accounts, processes and software.
          onesixtyone   # SNMP community-string sweep; skills/service-enumeration
                        # names it by hand in its SNMP section.
          nbtscan       # NetBIOS name/user enumeration over udp/137.
          ntp           # ntpq/ntpdc - `ntpdc -c monlist` reveals recent peers.
          tftp-hpa      # tftp client; unauthenticated config-file retrieval.
          ike-scan      # IKE/udp500 VPN endpoint + vendor fingerprinting.
          sipsak        # SIP/udp5060 probing and extension enumeration.
          avahi         # avahi-browse - mDNS/udp5353 service discovery.
        ];

        # Maintainer-only tooling: what the TEST SUITE needs, which is
        # deliberately NOT the same set as what the agents need at runtime.
        # nodejs in particular is not a Clicky runtime dependency at all -
        # nothing the plugin ships executes JavaScript outside the host CLI.
        # It exists solely so tests/syntax/check_js_syntax.sh can parse
        # workflows/*.js; that script falls back to `nix build nixpkgs#nodejs`
        # when node isn't on PATH, and this shell is the declared, pinned way
        # to get it. Keeping it out of clickyShell below means an engagement
        # never carries a JS runtime it has no use for.
        clickyDevShell = pkgs.mkShell {
          name = "clicky-dev";
          packages = with pkgs; [
            nodejs   # tests/syntax/check_js_syntax.sh (fallback checker)
            eslint   # tests/syntax/check_js_syntax.sh (preferred: adds no-undef)
            jq       # skills/engagement-state/scripts/*.sh, several test suites
            python3  # generators under tools/, python test suites
          ];
        };

        clickyShell = pkgs.mkShell {
          name = "clicky-pentest-toolchain";

          # Everything Kalilix's #kali shell provides, unchanged and still
          # owned upstream.
          inputsFrom = [ kalilix.devShells.${system}.kali ];

          packages = clickyExtraTools;
        };
      in
      {
        devShells = {
          default = clickyShell;
          # Explicit name so `nix print-dev-env <flake>#clicky` in launch.sh
          # doesn't depend on which shell happens to be `default`.
          clicky = clickyShell;
          # `nix develop .#dev` - for running tests/run_all.sh, not engagements.
          dev = clickyDevShell;
        };
      });
}
