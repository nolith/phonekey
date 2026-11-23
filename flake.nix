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

      # Unit and in-process integration tests, built with the package's
      # toolchain and vendored modules. The e2e tests need Docker and a
      # browser, so they run outside Nix: go test -tags e2e ./e2e
      checks = forAll (pkgs: {
        tests = self.packages.${pkgs.stdenv.hostPlatform.system}.default.overrideAttrs {
          name = "phonekey-tests";
          subPackages = [ "internal/..." ];
          doCheck = true;
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
          # The sandbox every instance runs in, so that a compromised phonekeyd
          # (a bug, or a malicious dependency) can't reach beyond its own state:
          # not other services, accounts or instances on the host.
          sandbox = name: {
            User = user name;
            Group = user name;
            StateDirectory = "phonekeyd/${name}";
            StateDirectoryMode = "0700";
            UMask = "0077";
            CapabilityBoundingSet = "";
            AmbientCapabilities = "";
            NoNewPrivileges = true;
            PrivateUsers = true;
            PrivateTmp = true;
            PrivateDevices = true;
            PrivateIPC = true;
            RemoveIPC = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            # The process can't see other accounts' processes in /proc.
            ProtectProc = "invisible";
            ProcSubset = "pid";
            ProtectClock = true;
            ProtectHostname = true;
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectKernelLogs = true;
            ProtectControlGroups = true;
            RestrictNamespaces = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            SystemCallArchitectures = "native";
            # EPERM rather than a kill: Go's runtime calls setrlimit at startup.
            SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
            SystemCallErrorNumber = "EPERM";
            # The host's tailscaled and D-Bus are off limits.
            InaccessiblePaths = [ "-/run/tailscale" "-/run/dbus" "-/var/run/dbus" ];
            MemoryMax = "512M";
            TasksMax = 256;
          };
          # systemd-run's -p form of a service config.
          toProperties = attrs: lib.concatLists (lib.mapAttrsToList (k: v:
            [ "-p" "${k}=${if lib.isList v then lib.concatStringsSep " " (map toString v) else if lib.isBool v then lib.boolToString v else toString v}" ]
          ) attrs);
          # Admin commands (pair-code, devbox add, keys) on an instance's
          # database: run as its account, in its sandbox, without network.
          ctl = pkgs.writeShellScriptBin "phonekeyd-ctl" ''
            if [ $# -lt 2 ]; then
              echo "usage: phonekeyd-ctl INSTANCE COMMAND [ARGS...]" >&2
              echo "instances: ${lib.concatStringsSep " " (lib.attrNames instances)}" >&2
              exit 2
            fi
            name=$1; shift
            case "$name" in
            ${lib.concatMapStrings (name: ''
              ${name}) exec ${config.systemd.package}/bin/systemd-run --quiet --pipe --wait --collect --service-type=exec \
                ${lib.escapeShellArgs (toProperties (sandbox name // { PrivateNetwork = true; }))} \
                -- ${lib.getExe cfg.package} --db ${stateDir name}/phonekey.db "$@" ;;
            '') (lib.attrNames instances)}
            *) echo "phonekeyd-ctl: unknown instance $name" >&2; exit 2 ;;
            esac
          '';
          # Where a TCP listener is used, incoming connections must stay
          # possible, so the address restrictions only apply otherwise.
          tcpListener = name: i: listen name i != null && !lib.hasPrefix "unix:" (listen name i);
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
              ipAddressAllow = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                example = [ "192.168.1.1" ];
                description = ''
                  Addresses the instance may reach despite the ban on the host,
                  link-local, private and tailnet ranges, e.g. a DNS resolver on the
                  LAN. systemd-resolved's stub, Tailscale's MagicDNS resolver and
                  networking.nameservers are always allowed.
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
            ]) instances) ++ [
              {
                # Browsers treat every port of a hostname as one site: instances
                # sharing the host's name would share cookies and passkeys.
                assertion = lib.length (lib.filter (i: i.serve.httpsPort != null) (lib.attrValues instances)) <= 1;
                message = "services.phonekeyd: at most one instance can use serve.httpsPort (the host's hostname); give the others tailscale.hostname.";
              }
            ];

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
                  RuntimeDirectory = user name;
                  RuntimeDirectoryMode = "0750";
                  Restart = "on-failure";
                  # Outbound HTTPS for push; netlink only for tsnet.
                  RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ]
                    ++ lib.optional (i.tailscale.hostname != null) "AF_NETLINK";
                } // sandbox name // lib.optionalAttrs (!tcpListener name i) {
                  # Nothing on the host or the local networks: push services and
                  # the tailnet's control and relay servers are on the internet.
                  # (tsnet's own tailnet traffic is userspace and needs ACLs.)
                  IPAddressDeny = [ "localhost" "link-local" "multicast" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "100.64.0.0/10" "fc00::/7" ];
                  # systemd-resolved's stub, and Tailscale's MagicDNS (IPv4, IPv6).
                  IPAddressAllow = [ "127.0.0.53" "100.100.100.100" "fd7a:115c:a1e0::53" ] ++ config.networking.nameservers ++ i.ipAddressAllow;
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
                  # Root, but only to talk to tailscaled's socket.
                  PrivateNetwork = true;
                  PrivateTmp = true;
                  PrivateDevices = true;
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  NoNewPrivileges = true;
                  ProtectKernelTunables = true;
                  ProtectKernelModules = true;
                  ProtectControlGroups = true;
                  RestrictAddressFamilies = [ "AF_UNIX" ];
                  CapabilityBoundingSet = "";
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
