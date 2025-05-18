{inputs, ...}: {
  perSystem = {
    config,
    pkgs,
    system,
    inputs',
    self',
    ...
  }: let
    # packages required for building the rust packages
    extraPackages = [
      pkgs.pkg-config
    ];
    withExtraPackages = base: base ++ extraPackages;

    craneLib = (inputs.crane.mkLib pkgs).overrideToolchain self'.packages.rust-toolchain;

    common-build-args = rec {
      src = inputs.nix-filter.lib {
        root = ../.;
        include = [
          "crates"
          "Cargo.toml"
          "Cargo.lock"
        ];
      };

      pname = "stowage";

      nativeBuildInputs = withExtraPackages [];
      LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath nativeBuildInputs;
    };

    deps-only = craneLib.buildDepsOnly ({} // common-build-args);

    packages = {
      default = packages.cli;
      cli = craneLib.buildPackage ({
          pname = "stowage-cli";
          cargoArtifacts = deps-only;
          cargoExtraArgs = "--bin stowage-cli";
          meta.mainProgram = "stowage-cli";
        }
        // common-build-args);

      cargo-doc = craneLib.cargoDoc ({
          cargoArtifacts = deps-only;
        }
        // common-build-args);
      mount = craneLib.buildPackage ({
          pname = "stowage-cmd-mount";
          cargoArtifacts = deps-only;
          cargoExtraArgs = "--bin stowage-cmd-mount";
          meta.mainProgram = "stowage-cmd-mount";
        }
        // common-build-args);
    };

    checks = {
      clippy = craneLib.cargoClippy ({
          cargoArtifacts = deps-only;
          cargoClippyExtraArgs = "--all-features -- --deny warnings";
        }
        // common-build-args);

      rust-fmt = craneLib.cargoFmt ({
          inherit (common-build-args) src;
        }
        // common-build-args);

      rust-tests = craneLib.cargoNextest ({
          cargoArtifacts = deps-only;
          partitions = 1;
          partitionType = "count";
        }
        // common-build-args);
    };
  in rec {
    inherit packages checks;

    apps = {
      cli = {
        type = "app";
        program = pkgs.lib.getBin self'.packages.cli;
      };
      default = apps.cli;
    };

    legacyPackages = {
      cargoExtraPackages = extraPackages;
    };
  };
}
