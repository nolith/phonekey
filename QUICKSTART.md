# Quickstart: NixOS, Tailscale, iPhone

One concrete setup, end to end:
- the backend on a NixOS host, as its own tailnet machine
- an iPhone as the approver
- the agent on a NixOS dev box (the same machine or another one), which also
  offers the keys of a 1Password agent forwarded from your Mac, so you can
  approve with 1Password at the desk and with the phone everywhere else
  ([forwarding 1Password](#forwarding-1password))

Replace `YOURTAILNET` with your tailnet's name (e.g. `tail1234ab`), and `you` with
your user name. The [README](README.md) covers the other setups and how it all
works.

Before you start: in the Tailscale admin console, under DNS, MagicDNS and HTTPS
certificates must be on.

## 1. The backend

In the host's system flake (`/etc/nixos/flake.nix`):

```diff
   inputs = {
     nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
+    phonekey.url = "github:stancl/phonekey";
+    phonekey.inputs.nixpkgs.follows = "nixpkgs";
   };

-  outputs = { nixpkgs, ... }: {
+  outputs = { nixpkgs, phonekey, ... }: {
     nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
       modules = [
         ./configuration.nix
+        phonekey.nixosModules.phonekeyd
+        {
+          services.phonekeyd.instances.you = {
+            vapidSubject = "https://phonekey.YOURTAILNET.ts.net";
+            tailscale.hostname = "phonekey";
+          };
+        }
       ];
```

```sh
sudo nixos-rebuild switch --flake /etc/nixos#myhost
journalctl -u phonekeyd-you -f
```

The log shows a `login.tailscale.com` link. Open it and approve the new
`phonekey` machine. A few seconds later the log says
`listening url=https://phonekey.YOURTAILNET.ts.net`. The site can take a minute
to load the first time, while the certificate is issued.

Two lines can be ignored:
- `interfaces: failed to read /proc/net/route` (the sandbox hides it)
- `no --vapid-subject set` (only shown if you left `vapidSubject` out)

## 2. The phone

1. Open `https://phonekey.YOURTAILNET.ts.net` in Safari, then Share → **Add to
   Home Screen**, and open phonekey from the home screen. Push notifications
   only work in the installed app.
2. On the host: `sudo phonekeyd-ctl you pair-code`. Enter the code in the app.
3. Tap **Create passkey**. For iCloud Keychain, pick *Passwords* if iOS offers
   1Password first.
4. Copy the `ssh-ed25519 …` key it shows.
5. Under **Notifications, grants and keys**: **Enable notifications**, then
   **Send test**.

On GitHub, add the key as a **Signing key**, and as an **Authentication key**
once you trust the setup.

## 3. The dev box

Register it on the backend host, and keep the token it prints; it's only shown
once:

```sh
sudo phonekeyd-ctl you devbox add mydevbox
```

On the dev box, store the token where only you can read it:

```sh
mkdir -p ~/.config/phonekey
echo 'pkd_…' > ~/.config/phonekey/token
chmod 600 ~/.config/phonekey/token
```

In the dev box's system flake (with the same `phonekey` input as above; on
the same machine as the backend, `phonekey.nixosModules.default` brings both
modules):

```nix
phonekey.nixosModules.phonekey-agent
{
  programs.phonekey-agent.users.you = {
    backend = "https://phonekey.YOURTAILNET.ts.net";
    # Also offer the keys of the forwarded 1Password agent, while it's connected.
    upstream = "$XDG_RUNTIME_DIR/op-agent.sock";
    # Names for `phonekey-use`.
    identities = { phone = "~/.ssh/phonekey.pub"; desktop = "~/.ssh/op-github.pub"; };
    # For github.com, use the agent and the key ~/.ssh/active.pub points at.
    ssh.github = true;
  };
}
```

That gives `you`:
- the agent as a systemd user service
- `phonekey-agent`, `phonekey-keygen` and `phonekey-use` in your `PATH`
- for github.com, ssh going through the agent with only the key
  `~/.ssh/active.pub` points at. Every other host keeps your usual setup: your
  `~/.ssh` keys and `SSH_AUTH_SOCK`. `ssh.identityAgent = true` would send
  every host through the agent.

These live in the system's ssh_config; your own `~/.ssh/config` still wins.
Nothing needs `SSH_AUTH_SOCK`.

```sh
sudo nixos-rebuild switch --flake /etc/nixos#mydevbox
systemctl --user start phonekey-agent      # from the next login on it starts by itself
journalctl --user -u phonekey-agent -f
```

## 4. Your keys and tools

Save the phone key, and make it the active one:

```sh
SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/phonekey-agent.sock ssh-add -L | grep '<the start of your key>' > ~/.ssh/phonekey.pub
phonekey-use phone
```

```nu
# the same in nushell
with-env { SSH_AUTH_SOCK: $"($env.XDG_RUNTIME_DIR)/phonekey-agent.sock" } { ssh-add -L } | lines | where $it =~ '<the start of your key>' | save -f ~/.ssh/phonekey.pub
phonekey-use phone
```

Check that signing works, before touching any other config:

```sh
echo hello | phonekey-keygen -Y sign -f ~/.ssh/phonekey.pub -n file
```

A notification arrives on the phone. After you approve, the command prints a
`-----BEGIN SSH SIGNATURE-----` block. This goes through the same
`phonekey-keygen` and agent that git and jj will use, and works the same in
nushell.

git, jj and ssh sign with whatever `~/.ssh/active.pub` points at. Switch with:
- `phonekey-use phone`: approve on the phone
- `phonekey-use desktop`: approve with 1Password; needs the forwarded agent,
  see [below](#forwarding-1password)
- `phonekey-use` on its own shows the current one

**git** (`~/.config/git/config`). `phonekey-keygen` finds the agent by itself:

```ini
[gpg]
	format = ssh
[gpg "ssh"]
	program = phonekey-keygen
[user]
	signingkey = ~/.ssh/active.pub
```

**jj** (`~/.config/jj/config.toml`). Nothing is signed automatically; you sign
deliberately, with `jj sign -r a..d` before pushing:

```toml
[signing]
behavior = "drop"
backend = "ssh"
key = "~/.ssh/active.pub"

[signing.backends.ssh]
program = "phonekey-keygen"
```

Signing a range is one command, so it's one approval: tap **Approve + rest of
"jj sign …"** on the first commit, and the others are signed as they come in.

ssh needs no config of your own for GitHub: the module sets it up.

## 5. Try it

```sh
ssh -T git@github.com     # once the key is an Authentication key on GitHub
jj sign -r 'trunk()..@-'  # sign everything not yet on trunk
jj git push
```

A notification arrives on the phone for each command. Open it and tap
**Approve**, or **Approve + rest of "…"** when the command signs several
commits.

## Updating

After new commits are pushed to the phonekey repository:

```sh
sudo nix flake update phonekey --flake /etc/nixos
sudo nixos-rebuild switch --flake /etc/nixos#myhost
systemctl --user restart phonekey-agent    # on dev boxes
```

The database, the tailnet machine and your passkey stay. No re-pairing is
needed unless the hostname changes.

## When something's off

- **`Load key "….pub": bad permissions` / `Permission denied (publickey)`.** The
  agent ssh talks to doesn't have that key. Either the agent isn't running
  (`systemctl --user status phonekey-agent`), your own `~/.ssh/config` points
  ssh at another agent, or `active.pub` points at the 1Password key while the
  forwarded agent isn't connected.
- **The agent doesn't start:** it waits for `~/.config/phonekey/token`. Check
  `systemctl --user status phonekey-agent`.
- **No notification:** check **Send test** in the app, and that the request
  shows up in the app at all (if so, it's the notification side).
- **The page shows "reconnecting…":** it reconnects by itself; **Reload** in
  the header forces it.

## Forwarding 1Password

For `phonekey-use desktop`, the dev box needs your Mac's 1Password agent. A
dedicated ssh host on the Mac forwards it to a fixed path on the dev box, which
`upstream` above points at. In the Mac's `~/.ssh/config`:

```
Host devbox-agent
  HostName devbox
  RemoteForward /run/user/1000/op-agent.sock "/Users/YOU/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
  ExitOnForwardFailure yes
  ServerAliveInterval 30
  ServerAliveCountMax 3
  SessionType none
```

- **Running it:** `ssh devbox-agent` opens no shell; it only holds the
  forwarding open. Keep it running while you work at the Mac.
- **The path:** `/run/user/1000` is your `$XDG_RUNTIME_DIR` on the dev box
  (`1000` is your user id there).
- **On the dev box,** sshd must be allowed to replace a stale socket from an
  earlier connection, or the forwarding fails after the first disconnect:
  ```nix
  services.openssh.settings.StreamLocalBindUnlink = "yes";
  ```
