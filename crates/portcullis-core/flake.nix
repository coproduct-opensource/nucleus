{
  description = "Aeneas pipeline: portcullis-core → Lean 4 for HeytingAlgebra verification";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    aeneas.url = "github:AeneasVerif/aeneas";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, aeneas, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Charon requires a specific nightly toolchain
        charonRust = pkgs.rust-bin.nightly."2026-02-07".default.override {
          extensions = [ "rustc-dev" "llvm-tools-preview" "rust-src" ];
        };

        aeneasPkg = aeneas.packages.${system}.default;
        charonPkg = aeneas.packages.${system}.charon or null;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            aeneasPkg
            charonRust
            pkgs.lean4
          ] ++ pkgs.lib.optionals (charonPkg != null) [ charonPkg ];

          shellHook = ''
            echo "Aeneas pipeline development shell"
            echo "  charon:  $(charon --version 2>/dev/null || echo 'use nix run github:aeneasverif/aeneas#charon')"
            echo "  aeneas:  $(aeneas --version 2>/dev/null || echo 'available')"
            echo "  rustc:   $(rustc --version)"
            echo ""
            echo "Usage:"
            echo "  1. Extract MIR:  charon --cargo --crate portcullis-core"
            echo "  2. Translate:    aeneas -backend lean portcullis-core.llbc"
            echo "  3. Verify:       cd lean && lake build"
          '';
        };

        # Script to run the full pipeline
        apps.translate = flake-utils.lib.mkApp {
          drv = pkgs.writeShellScriptBin "translate-portcullis-core" ''
            set -euo pipefail
            echo "=== Step 1: Charon MIR extraction ==="
            cd ${toString ./.}
            charon --cargo --crate portcullis-core
            echo ""
            echo "=== Step 2: Aeneas translation (Lean 4) ==="
            aeneas -backend lean portcullis-core.llbc -dest lean/generated
            echo ""
            echo "=== Done ==="
            echo "Generated Lean files in lean/generated/"
            echo "Run 'cd lean && lake build' to verify"
          '';
        };
      });
}
