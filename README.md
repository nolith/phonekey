# phonekey (PoC)

Approve SSH logins and commit signatures on your phone with a passkey. An
ssh-agent on the dev box hands each signing request to `phonekeyd`, which
pushes a notification to a web app. The web app derives an ordinary
`ssh-ed25519` key from the passkey's PRF output, signs, and forgets the key.

Design brief: <https://claude.ai/artifact/U11KvJataYt3YFH1ncZSKN>

## Layout

| Path | What |
| --- | --- |
| `cmd/phonekeyd` | backend: queue, dev box API, web API, Web Push, embedded web app, SQLite |
| `cmd/phonekey-agent` | ssh-agent for the dev box |
| `cmd/phonekey-keygen` | `ssh-keygen` shim for jj so the phone can show jj commits (see below) |
| `cmd/phonekey-sim` | fake phone: same web API as the page, key from a fixed secret |
| `web/` | approval web app (no build step, no third-party scripts except vendored `noble-ed25519`) |
| `internal/` | `server`, `store`, `agent`, `sshwire` (userauth/SSHSIG/session-bind parsing), `keyderive`, `protocol`, `sim` |
| `e2e/` | end-to-end tests: real OpenSSH/git/jj against an sshd container, and the real page in headless Chromium |

```sh
nix develop                 # go, openssh, git, jj, chromium
go build -o bin/ ./cmd/...
go test ./internal/...      # unit + in-process integration
go test -tags e2e ./e2e     # needs docker and chromium; builds a small alpine sshd image
```

The e2e tests never touch your real setup: temporary `HOME`, `GIT_CONFIG_GLOBAL`,
`JJ_CONFIG`, `ssh -F /dev/null` with explicit known_hosts and `IdentityAgent`.
Each test starts its own sshd container and removes it afterwards.

## What's verified

Automated, on this box (OpenSSH 10.6p1, git 2.56, jj 0.47.1, Chromium 158):

- `git clone`/`push` over SSH through the agent, with `session-bind@openssh.com`
  verified and the server named from known_hosts; unbound sessions refused.
  As in OpenSSH's ssh-agent, userauth is only signed for the most recent
  binding on a connection and never for one made to forward the agent; logins
  through a forwarded agent are flagged on the phone.
- `git commit -S` and `git tag -s`: the agent reads git's buffer file, checks
  its hash against the SSHSIG blob, and the phone sees author/subject/body.
  `git verify-commit` / `verify-tag` pass.
- `git rebase --gpg-sign` over 3 commits: 3 requests sharing one grant scope.
  In the page, *Approve + rest of "git rebase …"* signs the first and the
  grant signs the other two; no grant is offered for a lone `ssh-keygen`.
- While a grant may be open, a request from the same command holds its push
  back for 2 s and drops it if the grant signed it, so auto-signed requests
  don't each produce a notification.
- jj with `revsets.git-sign-on-push`: `jj git push` of two commits = 2 SSHSIG
  + 1 login, all in one scope; with `phonekey-keygen` the phone sees both
  commit subjects and jj change ids (from the commit's `change-id` header). Pushed commits verify with plain git and `jj log` says `good`.
- Deny on the phone fails the push; Ctrl-C (SIGINT to the process group)
  cancels the request on the backend; no answer → agent gives up at its deadline.
- Of two requests pending at once, only the one that arrived first (or the
  one whose notification was tapped) is preselected.
- The real page in headless Chromium with a virtual authenticator that
  supports PRF: create passkey → derive → pair → approve an `ssh-keygen -Y
  sign` → grant auto-signs the remaining 2 commits of a rebase → the
  diagnostics "Sign test message" output verifies with `ssh-keygen -Y verify`.
  The page's HKDF output is byte-identical to the Go mirror, and Chromium's
  WebCrypto Ed25519 passes the RFC 8032 vectors. The diagnostics signature is
  also checked with the noble-ed25519 fallback forced.
- Push: VAPID-signed, aes128gcm-encrypted request reaches a (fake) push service.
- *Recent* shows whether you or a grant signed each request, the command it
  came from, and the same details as the pending card.

Not verifiable here (needs your devices): PRF on iOS (iCloud Keychain and
1Password), in the home-screen app; Safari's Ed25519; real push delivery;
same key on iPhone and Mac; GitHub. See the checklist below.

## Try it locally without a phone

```sh
export PHONEKEY_DB=/tmp/phonekey.db
bin/phonekeyd serve --addr 127.0.0.1:8080 &
TOKEN=$(bin/phonekeyd devbox add mybox)
bin/phonekey-sim --url http://localhost:8080 pair "$(bin/phonekeyd pair-code)"
PHONEKEY_TOKEN=$TOKEN bin/phonekey-agent --backend http://localhost:8080 --socket /tmp/pk.sock &
bin/phonekey-sim --url http://localhost:8080 watch --ask &   # prompts y/N per request
SSH_AUTH_SOCK=/tmp/pk.sock ssh-add -L
```

`localhost` is a secure context, so the page itself also works at
<http://localhost:8080> in a desktop browser whose passkey provider supports
PRF; `e2e/browser_test.go` drives it that way with a CDP virtual authenticator.

## Phone checklist (milestone M0)

The phone needs HTTPS with a valid certificate. Easiest is Tailscale serve on
the box running phonekeyd (this changes your tailscale serve config, so it's
your call; `tailscale serve reset` undoes it):

```sh
bin/phonekeyd serve --addr 127.0.0.1:8080 --vapid-subject mailto:you@example.com
tailscale serve --bg http://127.0.0.1:8080     # https://<host>.<tailnet>.ts.net
```

The passkey (and so the derived key) is bound to that hostname. For the PoC
the passkey is throwaway; for real use pick the final domain first, or set
`--rp-id` to a parent domain.

1. **Safari on the iPhone**: open the URL, expand *Diagnostics*. Note the
   WebCrypto Ed25519 line (WebKit bug 262499). If it fails, the page uses
   noble automatically; you can force either one there.
2. `phonekeyd pair-code`, enter it, *Create passkey* with iCloud Keychain.
   If PRF isn't supported you'll get an explicit error. Copy the key it shows.
3. *Diagnostics → Sign test message*. Paste the shown snippet into a shell on
   any machine with OpenSSH: it must print `Good "phonekey-test" signature`.
4. *Diagnostics → Derive key* and note the fingerprint.
5. Share → *Add to Home Screen*, open it from there, repeat 3 and 4 inside the
   app. Same fingerprint = PRF works in the standalone app.
6. In the app: *Notifications → Enable*, then *Send test*.
7. On the Mac (Safari, then Chrome): open the URL, *Log in with passkey* with
   the synced iCloud passkey, *Derive key* → same fingerprint expected.
8. Repeat 2–5 with 1Password as the passkey provider (*Add another passkey*
   while logged in; no code needed). It derives a different key, which is fine.
9. Dev box: run the agent against it and `ssh-keygen -Y sign` something, or
   go straight to git (below). Then GitHub: add the key as an *Authentication*
   and a *Signing* key, `ssh -T git@github.com`, push a signed commit, check
   it shows Verified, and time how long GitHub waits during login (sets
   `--deadline`).

## Using it on a dev box

```sh
phonekey-agent --backend https://<host> --token-file ~/.config/phonekey/token \
  [--upstream /run/user/1000/op-agent.sock]   # also offer 1Password's keys
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/phonekey-agent.sock
ssh-add -L > ~/.ssh/phonekey.pub
```

git: `gpg.format = ssh`, `user.signingkey = ~/.ssh/phonekey.pub`.

jj:

```toml
[signing]
behavior = "drop"            # don't sign on every rewrite...
backend = "ssh"
key = "~/.ssh/phonekey.pub"

[signing.backends.ssh]
program = "phonekey-keygen"  # lets the phone show jj's commits

[revsets]
git-sign-on-push = "~signed() & mine()"   # ...sign when pushing
```

Without the shim jj pipes the commit to `ssh-keygen` on stdin and the phone
can only show "Sign git object for jj git push"; the signature is the same
either way.

## Knobs for the undecided parts

| Decision | Default | Where |
| --- | --- | --- |
| Grants | chosen per approval with *Approve + rest of "<command>"*; window 30 s, capped by the server | page *Grant length* setting, `phonekeyd serve --max-grant` (0 removes the button) |
| Agent deadline | 90 s | `phonekey-agent --deadline` (backend clamps to `--max-ttl`, 5 min) |
| Refuse unbound SSH logins | on | `--require-session-bind` |
| Refuse unknown hosts | off (hosts are named when known) | `--require-known-host`, `--known-hosts` |
| Key rotation / per-purpose keys | salt `phonekey/ssh-ed25519/v1` | `phonekeyd serve --salt` |
| RP ID | page hostname | `--rp-id` |
| Phone keys the agent offers | fetched from phonekeyd every 5 min | `phonekey-agent --keys FILE` |
| Ed25519 implementation | WebCrypto if it passes RFC 8032 vectors; every WebCrypto signature is checked with noble and redone with noble if wrong | page *Diagnostics* |
| Non-git signing data | refused | `--allow-unknown-kinds` |
| Web session | 30 days | `--session-ttl` |
| History retention | 7 days | `--retention` |

## Findings worth knowing

- `jj git clone` makes two SSH logins (two notifications without a grant).
- jj signs via stdin; `phonekey-keygen` exists only to make the content visible.
- x/crypto's agent server logs refused signatures to stderr itself
  (`agent 13: ...`), next to phonekey-agent's own log line.
- Approving needs a fresh PRF evaluation, so listing requests uses a separate
  long-lived session (established by signing a nonce with the derived key)
  rather than asking for Face ID just to look.
- phonekeyd refuses to queue data that isn't an SSH userauth payload or an
  SSHSIG blob, and the page refuses to sign its own login message format, so a
  dev box can't obtain a web-login signature.

Known gaps: `POST /api/web/nonce` is unauthenticated (one short-lived row per
call) and request creation sends a push each time, neither rate-limited. The
agent treats a client half-closing its socket as a disconnect; OpenSSH
doesn't do that.

Not done (M2/M3 in the brief): mode B (webauthn-sk signatures), NixOS modules,
rate limits, a pairing flow that approves new keys from an existing device
beyond "logged-in session may add keys".
