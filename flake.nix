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

      # The backend as NixOS services: one instance per person, each under its
      # own system account. The dev box side (phonekey-agent) is a per-user
      # process; see the README.
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.phonekeyd;
          instances = lib.filterAttrs (_: i: i.enable) cfg.instances;
          user = name: "phonekeyd-${name}";
          stateDir = name: "/var/lib/phonekeyd/${name}";
          socket = name: "/run/phonekeyd-${name}/http.sock";
          # The plain listener: an explicit address, or a socket only the
          # instance's account (and root's tailscaled) can open when it isn't
          # on its own tailnet machine.
          listen = name: i:
            if i.address != null then i.address
            else if i.tailscale.hostname == null then "unix:${socket name}"
            else null;
          # Admin commands (pair-code, devbox add, keys) on an instance's
          # database, as its account so file ownership stays right.
          ctl = pkgs.writeShellScriptBin "phonekeyd-ctl" ''
            if [ $# -lt 2 ]; then
              echo "usage: phonekeyd-ctl INSTANCE COMMAND [ARGS...]" >&2
              echo "instances: ${lib.concatStringsSep " " (lib.attrNames instances)}" >&2
              exit 2
            fi
            name=$1; shift
            case "$name" in
            ${lib.concatMapStrings (name: ''
              ${name}) exec ${pkgs.util-linux}/bin/runuser -u ${user name} -- ${lib.getExe cfg.package} --db ${stateDir name}/phonekey.db "$@" ;;
            '') (lib.attrNames instances)}
            *) echo "phonekeyd-ctl: unknown instance $name" >&2; exit 2 ;;
            esac
          '';
          instanceOptions = { name, ... }: {
            options = {
              enable = lib.mkEnableOption "this instance" // { default = true; };
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
                    Join the tailnet as its own machine with this name and serve
                    https://<hostname>.<tailnet>.ts.net. Nothing listens on the host.
                    Needs MagicDNS and HTTPS enabled for the tailnet.
                  '';
                };
                authKeyFile = lib.mkOption {
                  type = lib.types.nullOr lib.types.path;
                  default = null;
                  description = ''
                    Tailscale auth key for the first login. Without one, the service
                    logs a URL to approve the machine (journalctl -u phonekeyd-<name>).
                  '';
                };
              };
              serve.httpsPort = lib.mkOption {
                type = lib.types.nullOr lib.types.port;
                default = null;
                example = 8443;
                description = ''
                  Publish this instance through the host's tailscale serve on this
                  HTTPS port (https://<host>.<tailnet>.ts.net:<port>), proxying to the
                  instance's Unix socket. For instances without tailscale.hostname.
                '';
              };
              address = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                example = "127.0.0.1:8080";
                description = ''
                  Plain HTTP listener (host:port or unix:/path) instead of the
                  default: /run/phonekeyd-<name>/http.sock without
                  tailscale.hostname, nothing with it. The socket is open to the
                  account and group phonekeyd-<name> only; a reverse proxy such as
                  nginx gets access by joining that group. A TCP address is reachable
                  by every account on the host.
                '';
              };
              extraArgs = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                example = [ "--max-grant" "30s" ];
                description = "Extra arguments for `phonekeyd serve`.";
              };
            };
          };
        in
        {
          options.services.phonekeyd = {
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              description = "Package providing phonekeyd.";
            };
            instances = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule instanceOptions);
              default = { };
              description = ''
                Backends to run, one per person. Each runs as its own system account
                phonekeyd-<name>, with its state in /var/lib/phonekeyd/<name>.
              '';
            };
          };

          config = lib.mkIf (instances != { }) {
            assertions = lib.concatLists (lib.mapAttrsToList (name: i: [
              {
                assertion = builtins.match "[a-z][a-z0-9-]{0,21}" name != null;
                message = "services.phonekeyd.instances.${name}: names are lowercase letters, digits and dashes, at most 22 characters.";
              }
              {
                assertion = i.serve.httpsPort == null || (i.tailscale.hostname == null && i.address == null);
                message = "services.phonekeyd.instances.${name}: serve.httpsPort publishes the instance's Unix socket, so it can't be combined with tailscale.hostname or address.";
              }
              {
                assertion = i.serve.httpsPort == null || config.services.tailscale.enable;
                message = "services.phonekeyd.instances.${name}: serve.httpsPort needs services.tailscale.enable.";
              }
            ]) instances);

            users.users = lib.mapAttrs' (name: _: lib.nameValuePair (user name) {
              isSystemUser = true;
              group = user name;
              home = stateDir name;
            }) instances;
            users.groups = lib.mapAttrs' (name: _: lib.nameValuePair (user name) { }) instances;
            environment.systemPackages = [ ctl ];

            systemd.services = lib.mkMerge (lib.mapAttrsToList (name: i: {
              ${user name} = {
                description = "phonekey backend (${name})";
                wantedBy = [ "multi-user.target" ];
                wants = [ "network-online.target" ];
                after = [ "network-online.target" ];
                serviceConfig = {
                  ExecStart = lib.escapeShellArgs (
                    [ (lib.getExe cfg.package) "--db" "${stateDir name}/phonekey.db" "serve" "--vapid-subject" i.vapidSubject ]
                    ++ lib.optionals (listen name i != null) [ "--addr" (listen name i) ]
                    ++ lib.optionals (i.tailscale.hostname != null) [ "--tailscale-hostname" i.tailscale.hostname ]
                    ++ lib.optionals (i.tailscale.authKeyFile != null) [ "--tailscale-authkey-file" "%d/tailscale-authkey" ]
                    ++ i.extraArgs
                  );
                  LoadCredential = lib.optional (i.tailscale.authKeyFile != null) "tailscale-authkey:${i.tailscale.authKeyFile}";
                  User = user name;
                  Group = user name;
                  StateDirectory = "phonekeyd/${name}";
                  StateDirectoryMode = "0700";
                  RuntimeDirectory = user name;
                  RuntimeDirectoryMode = "0750";
                  UMask = "0077";
                  Restart = "on-failure";

                  # Other accounts on the host can't see or reach the process.
                  ProtectProc = "invisible";
                  ProcSubset = "pid";
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
              "${user name}-serve" = lib.mkIf (i.serve.httpsPort != null) {
                description = "tailscale serve for phonekey (${name})";
                wantedBy = [ "multi-user.target" ];
                after = [ "tailscaled.service" (user name + ".service") ];
                wants = [ "tailscaled.service" ];
                serviceConfig = {
                  Type = "oneshot";
                  RemainAfterExit = true;
                  ExecStart = "${lib.getExe config.services.tailscale.package} serve --bg --https=${toString i.serve.httpsPort} unix:${socket name}";
                  ExecStop = "${lib.getExe config.services.tailscale.package} serve --https=${toString i.serve.httpsPort} off";
                };
              };
            }) instances);
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
