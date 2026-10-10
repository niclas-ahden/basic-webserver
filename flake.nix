{
  description = "basic-webserver development environment";

  nixConfig = {
    extra-substituters = [ "https://niclas-ahden.cachix.org" ];
    extra-trusted-public-keys = [ "niclas-ahden.cachix.org-1:FdGli1vBk0cTuVJV27Tau/JvlbW+Ly3pRwFByyqdke0=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # nixos-unstable no longer supports Intel macOS.
    nixpkgs-x86-darwin.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
    # The Roc compiler revision, keep the `?dir=src` at the end. CI builds
    # this exact commit too, read from flake.lock.
    roc-src.url = "github:roc-lang/roc/5ba654b795c993767e6fd27b25bcde9e748b7cf9?dir=src";
    roc-nix = {
      url = "github:niclas-ahden/roc-nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.roc-src.follows = "roc-src";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs
    , nixpkgs-x86-darwin
    , roc-src
    , roc-nix
    , rust-overlay
    , ...
    }:
    let
      inherit (nixpkgs) lib;

      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = lib.genAttrs supportedSystems;
      rustToolchainConfig = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain;

      # scripts/build.py cross-compiles the host with `zig cc` for the musl
      # targets, so those work from any host. The macOS targets need an Apple
      # SDK for the bundled C dependencies, so only ship their standard
      # libraries where they can actually be built.
      muslRustTargets = [
        "x86_64-unknown-linux-musl"
        "aarch64-unknown-linux-musl"
      ];
      darwinRustTargets = [
        "x86_64-apple-darwin"
        "aarch64-apple-darwin"
      ];
      rustTargetsFor =
        system: muslRustTargets ++ lib.optionals (lib.hasSuffix "-darwin" system) darwinRustTargets;
      pkgsFor =
        system:
        import (if system == "x86_64-darwin" then nixpkgs-x86-darwin else nixpkgs) {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
    in
    {
      formatter = forAllSystems (system: (pkgsFor system).nixfmt);

      packages = forAllSystems (system: {
        roc = roc-nix.packages.${system}.roc;
        default = roc-nix.packages.${system}.roc;
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          roc = roc-nix.packages.${system}.roc;
          rustToolchain = pkgs.rust-bin.fromRustupToolchain (
            rustToolchainConfig
            // {
              targets = rustTargetsFor system;
              components = [ "rustfmt" "llvm-tools-preview" ];
            }
          );
        in
        {
          default = pkgs.mkShell {
            packages = [
              roc
              pkgs.python3
              rustToolchain
              pkgs.zig_0_16
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.valgrind ];

            shellHook = ''
              # scripts/regenerate_glue.py reads the glue spec from the pinned
              # compiler source. The input points at the repository's src
              # directory, so name the spec itself.
              export ROC_GLUE_SPEC=${roc-src}/glue/src/RustGlue.roc
              export ROC_LANGUAGE_SERVER_PATH=${roc}/bin/roc
            '';
          };
        }
      );
    };
}
