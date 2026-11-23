{
  description = "phonekey: approve SSH logins and commit signatures with a passkey";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
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
        };
      });
    };
}
