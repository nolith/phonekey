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
+        phonekey.nixosModules.default
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

Run the agent as a systemd user service, from the dev box's system flake (with
the same `phonekey` input as above):

```nix
({ pkgs, ... }: let
  agent = phonekey.packages.${pkgs.stdenv.hostPlatform.system}.phonekey-agent;
in {
  environment.systemPackages = [ agent ];  # phonekey-agent, and phonekey-keygen for jj
  systemd.user.services.phonekey-agent = {
    description = "phonekey ssh-agent";
    wantedBy = [ "default.target" ];
    # Runs for every user who has a token file.
    unitConfig.ConditionPathExists = "%h/.config/phonekey/token";
    serviceConfig = {
      # %h = home, %t = $XDG_RUNTIME_DIR. --upstream also offers the keys of a
      # forwarded 1Password agent while an `ssh -A` session is connected.
      ExecStart = "${agent}/bin/phonekey-agent --backend https://phonekey.YOURTAILNET.ts.net"
        + " --token-file %h/.config/phonekey/token --upstream %t/op-agent.sock";
      Restart = "on-failure";
    };
  };
})
```

```sh
sudo nixos-rebuild switch --flake /etc/nixos#mydevbox
systemctl --user start phonekey-agent      # from the next login on it starts by itself
journalctl --user -u phonekey-agent -f
```

## 4. Your shell and tools

Use the agent from your shell. In nushell's `env.nu`:

```nu
$env.SSH_AUTH_SOCK = $"($env.XDG_RUNTIME_DIR)/phonekey-agent.sock"
```

Save the phone key, and point the tools at a symlink so you can switch between
the phone and 1Password:

```sh
ssh-add -L | grep '<the start of your key>' > ~/.ssh/phonekey.pub
ln -sfn ~/.ssh/phonekey.pub ~/.ssh/active.pub
```

```nu
# in config.nu
alias mobile = ln -sfn ~/.ssh/phonekey.pub ~/.ssh/active.pub    # approve on the phone
alias desktop = ln -sfn ~/.ssh/op-github.pub ~/.ssh/active.pub  # approve with 1Password (needs ssh -A)
```

**git** (`~/.config/git/config`):

```ini
[gpg]
	format = ssh
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

**ssh** (`~/.ssh/config`):

```
Host github.com
  IdentityFile ~/.ssh/active.pub
  IdentitiesOnly yes
```

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
  agent ssh talks to doesn't have that key. Either `SSH_AUTH_SOCK` points
  elsewhere, the agent isn't running (`systemctl --user status
  phonekey-agent`), or `active.pub` points at the 1Password key while no
  `ssh -A` session is connected.
- **No notification:** check **Send test** in the app, and that the request
  shows up in the app at all (if so, it's the notification side).
- **The page shows "reconnecting…":** it reconnects by itself; **Reload** in
  the header forces it.
