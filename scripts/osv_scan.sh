#!/usr/bin/env bash
# OSV.dev sweep over the dependency surfaces GitHub's Dependabot
# alerts on. Exists because cargo-audit only sees the RustSec
# database — GHSA-only advisories (e.g. the 2026-03 libp2p-gossipsub
# remote-crash pair and the yamux Data-frame panic) never fire there.
# This script is the second eye that catches them.
#
# Coverage (be precise — each surface has different fidelity):
# - Cargo.lock: every crate, version-matched against OSV. Authoritative.
# - Gradle: direct "group:artifact:version" string literals only.
#   BOM-resolved artifacts (the Compose runtime) and plugins-DSL
#   versions (AGP/Kotlin/Hilt/Paparazzi) are NOT covered — Dependabot
#   has the same direct-coordinates limitation for non-lockfile Gradle.
# - GitHub Actions: OSV cannot version-match this ecosystem, so
#   actions are queried package-only and any advisory is surfaced as a
#   non-failing "check-action" line for manual triage against the
#   pinned ref.
#
# Failure policy: a version-matched advisory carrying any severity
# signal (GHSA id, database_specific.severity, or a CVSS severity[]
# entry) fails the run unless allowlisted below. Severity-less RustSec
# informational entries (unmaintained notices) are reported but never
# fail — they're tracked in .cargo/audit.toml and the README, and
# blocking CI on them would be noise.
set -euo pipefail
cd "$(dirname "$0")/.."

# The yamux allowlist entry below is justified ONLY while the 0.12
# engine stays dead code: libp2p-yamux's Config::default() selects the
# fixed 0.13 engine, and any call to Config::client()/server() or a
# config setter silently swaps in unpatched yamux 0.12. Fail loudly if
# such a call ever appears.
if grep -rnE "yamux::Config::(client|server)|WindowUpdateMode|set_(max_num_streams|receive_window_size|max_buffer_size|window_update_mode)" src/ tests/ 2>/dev/null; then
    echo "ERROR: non-default libp2p-yamux configuration detected." >&2
    echo "This activates the unpatched yamux 0.12 engine (GHSA-vxx9-2994-q338)" >&2
    echo "and invalidates the allowlist justification in this script." >&2
    exit 1
fi

# Allowlist: "advisory-id package version" -> justification. Binding
# to the exact package+version means any version movement forces a
# re-triage instead of inheriting a stale justification. Reviewed
# quarterly alongside .cargo/audit.toml.
ALLOWLIST=$(cat <<'EOF'
GHSA-vxx9-2994-q338|yamux|0.12.1|Linked unconditionally by libp2p-yamux 0.47 but dead code (guard above): runtime uses the 0.13 engine, and the lockfile's 0.13.10 is the fixed version. No patched 0.12.x exists upstream.
GHSA-3v94-mw7p-v465|hickory-proto|0.25.2|NSEC3 loop (= RUSTSEC-2026-0118): no fix on the 0.25 line libp2p consumes (fix is hickory 0.26); DNSSEC validation is never enabled, mDNS is opt-in. Tracked in .cargo/audit.toml.
GHSA-q2qq-hmj6-3wpp|hickory-proto|0.25.2|O(n^2) encoding (= RUSTSEC-2026-0119): fixed only in hickory 0.26, not yet adopted by libp2p-dns/mdns. Tracked in .cargo/audit.toml.
RUSTSEC-2026-0118|hickory-proto|0.25.2|Duplicate id for GHSA-3v94-mw7p-v465 (OSV mirrors both).
RUSTSEC-2026-0119|hickory-proto|0.25.2|Duplicate id for GHSA-q2qq-hmj6-3wpp (OSV mirrors both).
EOF
)

python3 - "$ALLOWLIST" <<'PY'
import json, re, subprocess, sys, time, urllib.error, urllib.request

allow = {}
for line in sys.argv[1].strip().splitlines():
    vid, pkg, ver, why = line.split("|", 3)
    allow[(vid, pkg, ver)] = why

def osv(path, payload=None, attempts=3):
    for i in range(attempts):
        try:
            req = urllib.request.Request(
                f"https://api.osv.dev/v1/{path}",
                data=json.dumps(payload).encode() if payload else None,
                headers={"Content-Type": "application/json"} if payload else {})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if i == attempts - 1:
                raise
        except Exception:
            if i == attempts - 1:
                raise
        time.sleep(2 ** (i + 1))

queries, labels = [], []

for m in re.finditer(
    r'^name = "([^"]+)"\nversion = "([^"]+)"', open("Cargo.lock").read(), re.M
):
    queries.append({"package": {"name": m[1], "ecosystem": "crates.io"}, "version": m[2]})
    labels.append(("crates.io", m[1], m[2]))

gav_re = re.compile(r"""['"]([\w.\-]+):([\w.\-]+):(\d[\w.\-]*)['"]""")
for path in ("build.gradle", "app/build.gradle", "settings.gradle"):
    try:
        text = open(path).read()
    except FileNotFoundError:
        continue
    for g, a, v in set(gav_re.findall(text)):
        queries.append({"package": {"name": f"{g}:{a}", "ecosystem": "Maven"}, "version": v})
        labels.append(("Maven", f"{g}:{a}", v))

# Actions (incl. subdirectory actions like codeql-action/upload-sarif):
# package-only — OSV has no version scheme for this ecosystem, so a
# version-qualified query silently matches nothing.
uses_re = re.compile(r"uses:\s*([\w.\-]+/[\w.\-]+)(?:/[\w.\-/]+)?@([\w.\-]+)")
listing = subprocess.run(
    ["find", ".github/workflows", "-name", "*.yml"], capture_output=True, text=True
).stdout.split()
actions = {}
for wf in listing:
    for name, ref in uses_re.findall(open(wf).read()):
        actions.setdefault(name, set()).add(ref)
for name in sorted(actions):
    queries.append({"package": {"name": name, "ecosystem": "GitHub Actions"}})
    labels.append(("GitHub Actions", name, "+".join(sorted(actions[name]))))

hits = []
for start in range(0, len(queries), 500):
    res = osv("querybatch", {"queries": queries[start:start + 500]})
    for i, r in enumerate(res["results"]):
        for vuln in r.get("vulns") or []:
            hits.append((labels[start + i], vuln["id"]))

failures = []
for (eco, name, ver), vid in sorted(set(hits)):
    d = osv(f"vulns/{vid}")
    if d is None:
        print(f"{'info':12} {'-':9} {eco:15} {name} {ver}: {vid} — withdrawn from OSV")
        continue
    sev = d.get("database_specific", {}).get("severity", "")
    cvss = bool(d.get("severity"))
    summary = d.get("summary", "")[:90]
    is_vuln = bool(sev) or cvss or vid.startswith("GHSA-")
    if eco == "GitHub Actions":
        verdict = "check-action"
    elif (vid, name, ver) in allow:
        verdict = "allowlisted"
    elif is_vuln:
        verdict = "FAIL"
        failures.append(f"{vid} ({name} {ver})")
    else:
        verdict = "info"
    print(f"{verdict:12} {sev or '-':9} {eco:15} {name} {ver}: {vid} — {summary}")

print(f"\nscanned {len(queries)} dependency queries across crates.io/Maven/GitHub Actions")
if failures:
    print("\nNon-allowlisted advisories — fix, or allowlist with a justification:")
    for f in failures:
        print(f"  {f}")
    sys.exit(1)
print("OSV scan clean (check-action lines, if any, need manual triage).")
PY
