{
  description = "eBPF development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }:
  let
    system = "x86_64-linux";

    pkgs = import nixpkgs {
      inherit system;
    };
  in
  {
    devShells.${system}.default = pkgs.mkShell {

      packages = with pkgs; [
        clang
        llvm
        rustc
        cargo
        libbpf
        bpftool
        git
        gnumake
        gcc
      ];

      shellHook = ''
        echo "eBPF dev environment loaded"
        echo "clang: $(clang --version | head -n1)"
        echo "rust: $(rustc --version)"
      '';
    };
  };
}

