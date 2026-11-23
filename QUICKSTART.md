# Quickstart: NixOS, Tailscale, iPhone

One concrete setup, end to end:
- the backend on a NixOS host, as its own tailnet machine
- an iPhone as the approver
- the agent on a NixOS dev box (the same machine or another one)

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
+    phonekey.url = "git+file:///home/you/phonekey";  # or github:…
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
    # Also offer a forwarded 1Password agent's keys (while `ssh -A` is connected).
    upstream = "$XDG_RUNTIME_DIR/op-agent.sock";
    # Names for `phonekey-use`.
    identities = { phone = "~/.ssh/phonekey.pub"; desktop = "~/.ssh/op-github.pub"; };
    # For github.com, sign in with ~/.ssh/active.pub only.
    ssh.github = true;
  };
}
```

That gives `you`:
- the agent as a systemd user service
- `phonekey-agent`, `phonekey-keygen` and `phonekey-use` in your `PATH`
- ssh pointed at the agent (`IdentityAgent`, in the system's ssh_config; your
  own `~/.ssh/config` still wins)

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

git, jj and ssh sign with whatever `~/.ssh/active.pub` points at. Switch with
`phonekey-use phone` (approve on the phone) or `phonekey-use desktop` (approve
with 1Password, which needs an `ssh -A` session). `phonekey-use` on its own
shows the current one.

**git** (`~/.config/git/config`). `phonekey-keygen` finds the agent by itself:

```ini
[gpg]
	format = ssh
[gpg "ssh"]
	program = phonekey-keygen
[user]
	signingkey = ~/.ssh/active.pub
```

**jj** (`~/.config/jj/config.toml`). Commits are signed when you push, so one
approval covers a whole push:

```toml
[signing]
behavior = "drop"
backend = "ssh"
key = "~/.ssh/active.pub"

[signing.backends.ssh]
program = "phonekey-keygen"

[revsets]
git-sign-on-push = "~signed() & mine()"
```

ssh needs no config of your own: the module sets it up.

## 5. Try it

```sh
ssh -T git@github.com     # once the key is an Authentication key on GitHub
jj sign -r @-             # or: jj git push
```

A notification arrives on the phone. Open it and tap **Approve**, or **Approve +
rest of "…"** when one command signs several times, like `jj git push` of
several commits.

## Updating

After committing changes in the phonekey repository:

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
  ssh at another agent, or `active.pub` points at the 1Password key while no
  `ssh -A` session is connected.
- **The agent doesn't start:** it waits for `~/.config/phonekey/token`. Check
  `systemctl --user status phonekey-agent`.
- **No notification:** check **Send test** in the app, and that the request
  shows up in the app at all (if so, it's the notification side).
- **The page shows "reconnecting…":** it reconnects by itself; **Reload** in
  the header forces it.
