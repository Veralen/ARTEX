# ARTEX — audit handoff

> Handoff from an audit session to a follow-up hardening/fix session.
> The audit session did **not** modify any tracked files. Everything below is
> findings + a plan. Add your own comments inline; `>` blocks or `<!-- -->` are fine.

---

## 0. Context the next session needs cold

- **What this repo is:** `BaaRai/ARTEX`, the English continuation fork of
  `Autumn-27/ARTEX` — an LLM-driven **autonomous black-box penetration-testing
  platform** (Go backend + embedded Next.js UI + Postgres). A planner decomposes
  a goal, workers run real offensive tools (`nmap`, `nuclei`, `sqlmap`, `ffuf`,
  `dalfox`, HTTP), and findings are tied to captured request/response traffic.
- **Why it's notable:** the original upstream was removed from GitHub (~Oct 2026)
  after the tool was used in real-world attacks (reports: South Korean banks;
  an FBI warning re: energy/manufacturing/telecom). Takedown did not kill it —
  forks persist. This checkout is one such fork.
- **This is NOT malware.** The news is about *misuse against third parties*, not a
  backdoor. The audit (section 2) found nothing hostile to the operator.
- **Scope boundary for all work here:** build / harden / run against **systems you
  own or are authorized in writing to test**. Everything in this handoff assumes
  that boundary.

### Environment facts / gotchas
- Go module path is `github.com/Autumn-27/artex` (upstream namespace) even though
  the repo is `BaaRai/ARTEX`. Don't "fix" this — import paths depend on it.
- `go.mod` has: `replace github.com/Autumn-27/norma => github.com/BaaRai/Norma v0.4.11`.
  **Norma is the agent core** (the LLM loop, tool framing, untrusted-output
  boundary). It is a separate fork and must be audited/vendored alongside ARTEX.
- Go 1.26.x. Build the real binary with the frontend embedded:
  `CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex` (needs
  `web/out` copied to `server/webui/dist` first — see README Option 4).
- Dev branch in use this session: `claude/keen-wright-2exbf6`.
- **This session ran on Opus 4.8 (a fallback from the configured Opus 5.5).**
  Noted in case model behavior is relevant to anything odd observed later.

---

## 1. The user's four questions — answers on record

1. **Useful against your own code?** It's a *dynamic* tester, not a source
   scanner — it attacks a **running** app over the network, it never reads your
   repo for bugs. Useful only against a deployed app / lab / staging copy you
   own. **Never prod** (see the destructive-command gaps in 3b). Costs LLM tokens
   continuously; for routine code audits, SAST + OWASP ZAP cover more for less.
2. **Reduce external deps to nil?** Literal zero is impossible (its job is
   LLM calls + target traffic), but the **supply-chain attack surface** can go to
   ~zero. Plan in section 4.
3. **Malicious otherwise?** No — see section 2.
4. **Refusal from Claude Code?** No, for own-systems/lab/authorized use. The line
   is unauthorized third-party targets or weaponization.

---

## 2. Audit verdict: not operator-hostile

Checked for exfil, backdoors, obfuscation, hostile install steps. Clean.

- **No phone-home.** Update check is opt-in (`ARTEX_UPDATE_CHECK=1`) and sends no
  identifiers — `server/update_check.go` (`fetchLatestRelease`, generic UA).
- **"Telemetry" is local only** — byte counts to your own Postgres, no content,
  no network — `llmrec/context_telemetry.go`.
- **Norma fork** (`github.com/BaaRai/Norma v0.4.11`) downloaded and verified
  against `go.sum` / Go checksum DB. ~21k LOC, 3 direct deps, no `init()` side
  effects, only talks to the LLM/search providers you configure.
- **No obfuscation** in either tree (searched encoded literals, `plugin.Open`,
  dynamic exec). The two `syscall.Exec` sites are the privilege-drop shim
  (`server/execpriv_unix.go`) and a secret-scrubbing re-exec
  (`server/envseal_linux.go`) — both behave as documented.
- **Dockerfile is above average:** base images pinned by digest, scanner binaries
  checked by sha256 (`Dockerfile` ~L16/29/70/110/186). Soft spots in 3c.
- **Browser extension clean** (`extension/`): attaches to one tab on explicit
  Start; its only `fetch` goes to the ARTEX URL you set (`background.js:148`).
- **Frontend clean:** no analytics/trackers; mainstream deps; fonts local.
- **Cosmetic:** a real public IP `107.172.96.177:8082` appears in a tool-
  description example — `traffic/traffic.go:2513`. Harmless, likely a leftover
  test target. Candidate cleanup.

**Caveat worth repeating:** forks proliferated after the takedown. This verdict
is for *this checkout*. Keep building only from the audited tree (which is the
point of vendoring, section 4).

---

## 3. Safety features weaker than the README implies (fix candidates)

These are the substantive findings. None is a "vuln in ARTEX against you"; they
are **under-guards** that matter the moment you run it. Good first targets for
the fix session.

### 3a. Bash target gate is a text-parse and misses ordinary usage
`intercept.ExtractTargets` only recognizes scheme URLs / IP literals / `host:port`
in the *command string*. Verified bypasses (all produce **no target**, so the
call runs — `intercept/target_gate.go:97`):
- bare hostnames: `nmap -sV offscope.example.org`, `curl offscope.example.org/x`,
  `sqlmap -u host/?id=1`
- shell-assembled / encoded / file-driven: `H=...; curl $H`, base64, `nuclei -l targets.txt`

Also: the gate is **off by default** and only enableable per-task via API. The
code comment is honest ("detects a declared target; does not prevent an
undeclared connection"); the README's "assets outside scope are not explored" is
not. Real enforcement needs the opt-in transparent proxy + your own iptables
(IPv4 only) — `docs/traffic-transparent.md`.

### 3b. Destructive-command blocklist has holes
Default intercept is a regex denylist seeded in `db/db.go` (~L436–720); on no
match **and** judge off (judge is off by default), the call is **allowed**
(`intercept/intercept.go:714` → caller allows). Verified NOT blocked:
`find / -delete`, `python -c 'shutil.rmtree(...)'`, `curl -X 'DELETE'` (quoted),
`curl --request=DELETE`, SQL `DELETE FROM`, `tar | base64 | curl -d @-`.
→ Mitigation for operators: enable the LLM judge or switch to allow-list/approval
rules. Possible fix: tighten patterns and/or default judge on.

### 3c. Privilege drop silently disabled when not run as root
Local-build / release-zip / `start.sh`-without-root path: the exec privilege drop
disables itself with one log line (`server/execpriv.go:63`), so the agent's Bash
runs **as your user** (your `~/.ssh`, cloud creds, etc.). Docker path is fine
(runs as root in-container, drops to uid 10001). Consider: refuse to start, or
loud warning, when drop is unavailable and not explicitly waived.

### 3d. Asset scope gate is allow-by-default
`EvaluateAssetGate` (`db/asset_intercept_match.go:199`): with no allow-list,
anything not block-listed is allowed. And it governs the asset graph, not Bash
egress. Operator fix: set a per-task allow-list every time.

### 3e. Dockerfile movable refs
`sqlmap` and `nuclei-templates` are `git clone --branch <tag>` (`Dockerfile`
~L131/151) — tags can be moved. Pin to commit SHAs or switch to
tarball+sha256 like the other assets.

---

## 4. Hardening plan for "dependencies → ~nil" (the fix session's main job)

Three distinct supply chains; "nil external deps" means **nothing fetched at
build time + no third-party cloud at runtime + traffic only to your chosen
target.**

### 4a. Go modules (incl. the Norma fork) — fully solvable
```bash
go mod vendor
# verify it builds with zero network + zero proxy:
cd web && npm ci && npm run build:static && cd ..
cp -r web/out server/webui/dist
GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex
```
`go.sum` already cryptographically pins every module, so a tampered upstream
can't silently swap in — vendoring just makes the build fetch nothing and puts
the audited source in-tree.

### 4b. Frontend npm tree — separate supply chain, decide explicitly
`web/package-lock.json` (~30+ deps) is its own chain. `npm ci` is pinned/
reproducible but still **fetches**. For a hermetic frontend build either prime an
offline npm cache or commit `web/node_modules`. **Flag this to the user as a
decision** — it's the piece most people forget when they say "vendor everything."

### 4c. Scanner toolchain (Docker) — pin the movable refs
Pin `SQLMAP_VERSION` / `NUCLEI_TEMPLATES_VERSION` clones to commit SHAs (or
tarball+sha256). Everything else in the Dockerfile is already digest/sha pinned.

### 4d. Runtime egress → local
- LLM: use **Ollama** (keyless, local) instead of Anthropic/OpenAI — removes the
  only unavoidable outbound call. `ARTEX_LLM_PROVIDER=ollama`.
- Keep `ARTEX_UPDATE_CHECK` unset (default). Then the only egress is to the target
  you point it at.

### 4e. Prove it
After 4a–4d, build and run with the module proxy and network blocked except the
target, and confirm a task runs end-to-end against a local lab app.

---

## 5. Build & test status (reproducible)

- `go build ./...` ✓ and `go vet ./...` ✓ — clean.
- Full `go test ./...`: **all 22 packages pass except the root-isolation tests**,
  and those failures were **environment artifacts, not code bugs**:
  - Isolation tests need the compiled test binary on a **world-traversable,
    executable** path. Default `GOTMPDIR` is `0700`, so the dropped uid 10001
    can't `exec` the test binary (exit 126). Repro the real result:
    ```bash
    go test -c -o /opt/artex-gotmp/server.test ./server   # 0755 dir
    chmod 755 /opt/artex-gotmp/server.test
    cd server && /opt/artex-gotmp/server.test -test.run 'IsolationSelfTest|ExecPriv|NNP' -test.v
    ```
    → **37 isolation/privilege-drop tests PASS** this way.
  - `TestConfinedFileToolsAsRoot` assumes root can read `/proc/1/environ`; this
    container blocks it. Not a code issue.
  - `TestConnectWithoutPasswordRealPG` correctly flagged the throwaway test DB,
    which I'd deliberately set to trust-auth.
- Postgres-backed tests: set `ARTEX_PG_DSN=postgres://.../db?sslmode=disable` and
  run with `-p 1` (packages share one test DB; parallel pkgs collide).

Confirmed-good (hold up as documented): argv-prefix matcher (all README examples),
untrusted-output boundary (random per-call nonce, embedded markers neutralized —
`Norma/harness/untrusted.go`), fail-closed on unreadable rule store / bad deny
patterns, constant-time setup token, in-process HTTP tools re-checked at dial.

---

## 6. Open decisions for the user
- [ ] Commit `web/node_modules` vs. offline npm cache for 4b?
- [ ] Default the LLM judge **on**, or just document "enable it"? (3b)
- [ ] Make missing privilege-drop a hard failure vs. loud warn? (3c)
- [ ] Worth filing an upstream issue that the README overstates the Bash target
      gate + scope defaults (3a/3d)? Or keep changes local to this fork?
- [ ] Remove the stray public IP in `traffic/traffic.go:2513`?

---

*Scratch artifacts from the audit (probe programs, test logs) live in the session
scratchpad, not in the repo. No tracked files were changed by the audit session.*
