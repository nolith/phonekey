{
  description = "phonekey: approve SSH logins and commit signatures with a passkey";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: {
        default = pkgs.buildGoModule {
          pname = "phonekey";
          version = "0.1.0";
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [ ./go.mod ./go.sum ./cmd ./internal ./web ];
          };
          vendorHash = "sha256-jR72jh6BY9G5zVY1s5pPlv+4xiUprdBn16HwSipkv/Q=";
          subPackages = [ "cmd/phonekeyd" "cmd/phonekey-agent" "cmd/phonekey-keygen" "cmd/phonekey-sim" ];
          env.CGO_ENABLED = "0";
          ldflags = [ "-s" "-w" ];
          meta.mainProgram = "phonekeyd";
        };
      });

      # The backend as a NixOS service. The dev box side (phonekey-agent) is a
      # per-user process; see the README.
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.phonekeyd;
          stateDir = "/var/lib/phonekeyd";
          db = "${stateDir}/phonekey.db";
          # Admin commands (pair-code, devbox add, keys) on the service's
          # database, as the service user so file ownership stays right.
          ctl = pkgs.writeShellScriptBin "phonekeyd-ctl" ''
            exec ${pkgs.util-linux}/bin/runuser -u phonekeyd -- ${lib.getExe cfg.package} --db ${db} "$@"
          '';
        in
        {
          options.services.phonekeyd = {
            enable = lib.mkEnableOption "the phonekey backend";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              description = "Package providing phonekeyd.";
            };
            address = lib.mkOption {
              type = lib.types.str;
              default = "127.0.0.1:8080";
              description = ''
                Plain HTTP listen address, for agents on this host, `tailscale serve`
                or a reverse proxy. An empty string disables it.
              '';
            };
            vapidSubject = lib.mkOption {
              type = lib.types.str;
              example = "mailto:you@example.com";
              description = "Contact for push services (a mailto: or https: URL).";
            };
            tailscale = {
              hostname = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                example = "phonekey";
                description = ''
                  Join the tailnet as this machine name and serve HTTPS at
                  https://<hostname>.<tailnet>.ts.net (needs MagicDNS and HTTPS
                  enabled for the tailnet). Independent of the host's own tailscaled.
                '';
              };
              authKeyFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = ''
                  File with a Tailscale auth key for the first login. Without one,
                  the service logs a URL to approve the machine
                  (`journalctl -u phonekeyd`).
                '';
              };
            };
            extraArgs = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [ "--max-grant" "30s" ];
              description = "Extra arguments for `phonekeyd serve`.";
            };
          };

          config = lib.mkIf cfg.enable {
            users.users.phonekeyd = {
              isSystemUser = true;
              group = "phonekeyd";
              home = stateDir;
            };
            users.groups.phonekeyd = { };
            environment.systemPackages = [ ctl ];

            systemd.services.phonekeyd = {
              description = "phonekey backend";
              wantedBy = [ "multi-user.target" ];
              wants = [ "network-online.target" ];
              after = [ "network-online.target" ];
              serviceConfig = {
                ExecStart = lib.escapeShellArgs (
                  [ (lib.getExe cfg.package) "--db" db "serve" "--addr" cfg.address "--vapid-subject" cfg.vapidSubject ]
                  ++ lib.optionals (cfg.tailscale.hostname != null) [ "--tailscale-hostname" cfg.tailscale.hostname ]
                  ++ lib.optionals (cfg.tailscale.authKeyFile != null) [ "--tailscale-authkey-file" "%d/tailscale-authkey" ]
                  ++ cfg.extraArgs
                );
                LoadCredential = lib.optional (cfg.tailscale.authKeyFile != null) "tailscale-authkey:${cfg.tailscale.authKeyFile}";
                User = "phonekeyd";
                Group = "phonekeyd";
                StateDirectory = "phonekeyd";
                StateDirectoryMode = "0700";
                Restart = "on-failure";

                NoNewPrivileges = true;
                PrivateTmp = true;
                PrivateDevices = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictNamespaces = true;
                RestrictRealtime = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                SystemCallArchitectures = "native";
                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" ];
              };
            };
          };
        };

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            openssh
            git
            jujutsu
            sqlite
            jq
          ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
            # Headless browser for the WebAuthn virtual-authenticator test.
            chromium
          ];
          env.CGO_ENABLED = "0";
          # Build with the toolchain from nixpkgs, as the package does, instead of
          # letting go download whatever go.mod asks for.
          env.GOTOOLCHAIN = "local";
        };
      });
    };
}
