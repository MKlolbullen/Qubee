# Skills

Professional capability map for a bug bounty hunter / penetration tester. Organised by what the work actually requires, not by certification taxonomy.

## Reconnaissance and asset discovery

- Passive recon: ASN/CIDR enumeration, certificate transparency mining (`crt.sh`, `censys`, `shodan`), historical DNS (`SecurityTrails`, `PassiveTotal`), GitHub/GitLab dorking for leaked secrets, `wayback` and `commoncrawl` for old endpoints.
- Active recon: subdomain brute-force and permutation (`amass`, `subfinder`, `dnsx`, `puredns`, `gotator`), wildcard detection, virtual-host enumeration, port and service fingerprinting (`nmap`, `naabu`, `masscan`), TLS fingerprinting (`tlsx`, `ja3`/`ja4`).
- Content discovery: `feroxbuster`/`ffuf` with tuned wordlists (`SecLists`, `assetnote`), JS endpoint extraction (`getJS`, `linkfinder`, `gau`, `katana`), parameter discovery (`arjun`, `paramspider`, `x8`).
- Scope discipline: read the program scope before touching anything, maintain an explicit out-of-scope list, never test third-party SaaS unless the program owns the tenant.

## Web application testing (OWASP-shaped, but deeper)

- **Injection**: SQLi (boolean-blind, time-based, second-order, OOB via `Burp Collaborator`/`interactsh`), NoSQL injection, command injection, SSTI (Jinja2, Twig, Velocity, Freemarker, ERB), LDAP/XPath/expression-language injection, prototype pollution (client and server).
- **AuthN/AuthZ**: IDOR (horizontal and vertical), broken object/function-level authorization, JWT flaws (`alg=none`, key confusion, weak HMAC, `kid` injection, JWKS spoofing), OAuth2/OIDC misconfiguration (open redirect on `redirect_uri`, PKCE downgrade, `state` reuse, mix-up attacks), SAML XML signature wrapping.
- **Session and CSRF**: SameSite/cookie-flag analysis, CSRF token oracle, login/logout CSRF, cross-origin leaks, session fixation.
- **Client-side**: DOM XSS (sources/sinks via `DOM Invader`), CSP bypass (JSONP gadgets, dangling markup, base-tag, script-gadget chains), postMessage origin checks, web message DOM clobbering, CSWSH on WebSocket upgrades.
- **SSRF**: cloud metadata exfiltration (IMDSv1/v2, GCP/Azure/Alibaba variants), gopher/dict/file smuggling, DNS rebinding, blind SSRF via timing/OOB, URL parser confusion.
- **Request smuggling**: HTTP/1.1 CL.TE / TE.CL / TE.TE, HTTP/2 downgrade smuggling, header normalisation differentials between front-end and back-end.
- **File handling**: arbitrary file read/write, path traversal, archive extraction (`Zip Slip`, tar symlink), polyglot uploads, `XXE` (in-band, OOB, blind via DTD), unsafe deserialization (Java, .NET, Python pickle, Ruby Marshal, PHP `__destruct` chains, Node.js `node-serialize`).
- **Race conditions**: single-packet attack (Turbo Intruder), TOCTOU on payment/coupon/withdrawal flows, idempotency-key abuse.
- **Cache poisoning / deception**: unkeyed input poisoning, fat-GET, parameter cloaking, web cache deception via path confusion.

## API testing

- REST: enumerate via OpenAPI/Swagger when published; otherwise harvest from JS/mobile traffic. Test mass-assignment, HTTP-verb tampering, content-type confusion, JSON↔XML parser switching.
- GraphQL: introspection (and bypasses when disabled — field suggestion, alias-based discovery), batching abuse, query-depth/complexity DoS, authorization on resolvers, CSRF on `application/json` queries that are smuggleable.
- gRPC: reflection enumeration, protobuf fuzzing (`grpcurl`, `ghz`), mTLS handling.
- Webhooks: SSRF via callback URL, signature-validation bypass, replay.

## Network and infrastructure

- Internal pentest: AD enumeration (`bloodhound-ce`, `ldapsearch`, `ldeep`), Kerberos abuse (Kerberoasting, AS-REP roasting, unconstrained/constrained delegation, S4U2Self/Proxy, Resource-Based Constrained Delegation), ADCS abuse (ESC1–ESC15 via `Certipy`), NTLM relay (`ntlmrelayx`, `Responder` with care for scope), SMB signing.
- Lateral movement primitives: WMI, WinRM, DCOM, SCM, schtasks, PsExec-class binaries — pick the quietest tool for the engagement, not the loudest.
- Egress + C2: pick infra to match the rules of engagement; document every callback domain. Profile-tune Cobalt Strike / Sliver / Mythic for traffic that fits the target's baseline. Do not deploy beaconing capability outside the scoped network.
- Wireless: WPA2/3 handshake capture, PMKID, evil twin, EAP-relay against misconfigured 802.1X.

## Cloud (AWS / GCP / Azure)

- IAM enumeration without alarms (`pacu`, `aws-recon`, `ScoutSuite`, `prowler`, `Stormspotter`, `MicroBurst`).
- Privilege-escalation paths: `iam:PassRole` chains, Lambda → role assumption, EC2 instance profile theft, S3 bucket policy/ACL misuse, GCP service-account-key creation, Azure managed-identity misuse.
- Cross-tenant: SaaS multi-tenant isolation review, signed-URL leakage, public storage with sensitive data.
- Container/K8s: Trivy/Grype image scans, kubelet 10250 exposure, RBAC review, escape-from-container patterns (privileged, hostPath, hostPID, capabilities), service-account token abuse.

## Mobile

- Android: APK static analysis (`apktool`, `jadx`, `MobSF`), insecure storage, exported components, deep-link hijacking, WebView misconfig (`addJavascriptInterface`, file scheme), root/debug detection bypass, `frida` instrumentation, certificate pinning bypass via `objection`/Frida hooks.
- iOS: IPA analysis with `class-dump`/`Hopper`/`Ghidra`, keychain auditing, URL-scheme abuse, jailbreak detection bypass, `frida-trace` on Objective-C / Swift.
- JNI/native crypto bridges: ensure the native side actually owns the secret material; verify there's no Java-side fallback. (Pattern is identical to the Rust-as-authority model in this repo.)

## Cryptography review

- Identify primitives in use and check against current guidance: AES-GCM (nonce reuse is fatal), ChaCha20-Poly1305, Ed25519/X25519, ECDSA (low-entropy `k` recovery, biased nonces), RSA (PKCS#1 v1.5 padding oracle, Bleichenbacher, common modulus, low exponent), HMAC vs unauthenticated MAC.
- Post-quantum awareness: ML-KEM-768 (FIPS 203), ML-DSA-44 (FIPS 204), hybrid signatures combining classical + PQ. Recognise migration patterns and review wire-format domain separation.
- Implementation review: constant-time comparisons, secret zeroisation on drop, `mlock`/`munlock` on sensitive buffers, RNG sourcing (no `Math.random()`/`thread_rng()` in security paths).
- Protocol review: replay protection (nonces/counters), domain separation tags, signature-over-canonical-bytes (not `bincode`/`serde` blobs), strict generation-counter gates on session/group key rotation.

## Source-code review (white-box)

- Read the build first: feature flags, conditional compilation (`cfg(target_os=…)`, `#if DEBUG`), dead code that's reachable via reflection or JNI.
- Trace tainted input from sources to sinks: HTTP handlers, deserialization entry points, file parsers, IPC boundaries, JNI/FFI bridges.
- Diff review for security-sensitive changes: auth, crypto, parsers, deserializers, sandbox boundaries. PR review is often higher-yield than fuzzing.
- Languages of working competence: C/C++, Rust, Go, Python, Java/Kotlin, JavaScript/TypeScript, C#, Ruby, PHP. Read enough to find the bug; write enough to prove it.

## Reverse engineering and binary analysis

- `Ghidra`, `IDA`, `Binary Ninja`, `radare2`/`r2`. Decompiler-driven for triage, disassembler for the part the decompiler lies about.
- Dynamic analysis: `gdb`/`lldb` with `pwndbg`/`gef`, `x64dbg`, `Frida` for runtime hooking on any platform with a JIT or interpreter.
- Memory-corruption primitives when in scope: stack/heap overflow, UAF, double-free, type confusion, integer overflow leading to undersized allocation; modern mitigations and known bypass classes (ASLR leaks, ROP/JOP, CFI weaknesses, kernel mitigation chaining).
- Fuzzing: `AFL++`, `libFuzzer`, `honggfuzz`, structure-aware fuzzers (`libprotobuf-mutator`), coverage-guided harnesses for parsers and deserializers; corpus minimisation and crash triage.

## Tooling fluency

- Burp Suite Pro at expert level: match-and-replace, session handling rules, custom extensions in Java/Kotlin/Jython, Turbo Intruder for race conditions and concurrency tests, Collaborator for OOB.
- Browser devtools, `mitmproxy`, `Caido` for asynchronous review, `httpx`/`nuclei` for fast templated checks (and writing your own templates).
- Linux comfort at the shell level: `awk`, `jq`, `xargs -P`, `parallel`, network namespaces for isolation, `tcpdump`/`Wireshark` with display filters.
- Build your own tool when the existing one ends two steps short of the bug. Don't pad reports with tool output that you can't explain line by line.

## Programming and automation

- Scripting: Python is the lingua franca; Go for concurrent network tools; Rust for memory-safe binaries you ship to clients.
- Write request-modification proxies, custom decoders, signature-relay glue, and one-off PoC servers fluently. A reproducible PoC is worth more than a paragraph of prose.
- Version control discipline on engagements: per-target repo, signed commits, redaction discipline before sharing artefacts.

## Reporting and communication

- Write the report the engineer who will fix it wants to read: clear title, business impact in one sentence, exact reproduction steps, request/response captures with timestamps, the smallest patch that closes the bug, references to the canonical class (CWE/OWASP) for the triage queue.
- CVSS and program-specific severity rubrics: be calibrated, not optimistic. Inflated severity destroys trust faster than missed bugs.
- Disclosure ethics: stay in scope, stop on access to sensitive data, never exfiltrate beyond proof, follow the program's disclosure window. If the program has no disclosure policy, treat it like CERT/CC's 90-day default.
- Build a report-writing template you reuse, but tune the executive summary to the audience every time.

## Mindset and methodology

- Read the docs and the source before the scanner. Most high-impact bugs come from understanding the application's intended trust model and finding where reality drifts from it.
- Form a hypothesis, design the smallest test that distinguishes it from the alternatives, run it, write down what you learned. Move on when the hypothesis is dead — don't anchor on a finding that isn't there.
- Keep a running notes file per target with endpoints, parameters, observed behaviours, and dead ends. The bug you find on day six is usually a recombination of facts you logged on day one.
- Time-box. A pentest is a budget, not an open-ended hunt. Bug bounty is the inverse — the budget is your patience, and the rate is finding what others have missed.
- Authorisation before everything. No engagement letter, no scope, no test. "Curiosity" is not a defence in any jurisdiction worth living in.

## Continuous learning

- Track: PortSwigger Research, Project Zero, Orange Tsai, James Kettle, Frans Rosén, watchTowr, Assetnote, Trail of Bits, NCC Group publications. Read primary sources, not summaries.
- Reproduce public CVEs end-to-end on a lab build at least once a month — it keeps tooling and reflexes sharp.
- CTFs (web, pwn, crypto, reverse) for the techniques the day job rarely exercises; HackTheBox / TryHackMe / RootMe / pwnable.kr / cryptohack for breadth.
- Read RFCs for protocols you test (HTTP/1.1, HTTP/2, HTTP/3, TLS 1.3, OAuth2, OIDC, SAML, WebAuthn). The bug is usually in the gap between the RFC and the implementation.
