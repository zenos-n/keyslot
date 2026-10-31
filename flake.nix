{
  description = "Keyslot GTK4/libadwaita client for KeePassXC databases";

  # Keep the reviewed KeePassXC core and its dependencies together.
  inputs.nixpkgs.url = "github:nixos/nixpkgs/c5c4a43b0e8056328ec4529f735cabdb8f1942bb";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          keyslot = import ./default.nix { inherit pkgs; };
        in {
          inherit keyslot;
          default = keyslot;
          engine = keyslot.engine;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.keyslot}/bin/keyslot";
          meta.description = self.packages.${system}.keyslot.meta.description;
        };
        keyslot = self.apps.${system}.default;
      });

      devShells = forAllSystems (system: {
        default = import ./shell.nix {
          pkgs = import nixpkgs { inherit system; };
        };
      });

      checks = forAllSystems (system: {
        # Opt-in development checks; ordinary packages build only the runtime.
        keyslot = import ./default.nix {
          pkgs = import nixpkgs { inherit system; };
          doCheck = true;
        };
        security-sanitizer = import ./engine/sanitizer.nix {
          pkgs = import nixpkgs { inherit system; };
        };
      });
    };
}
