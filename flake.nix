{
  description = "Indestructible ChipWhisperer Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        pythonPackages = pkgs.python3Packages;
        # The system C-libraries that pip wheels need
        dynamic-libs = with pkgs; [
          libusb1       # For pyusb/ChipWhisperer
          stdenv.cc.cc.lib # For PyZMQ/Jupyter
          zlib
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          name = "python-venv";
          venvDir = "./.venv";
          buildInputs = [
            pythonPackages.python
            pythonPackages.venvShellHook

            # Those are dependencies that we would like to use from nixpkgs, which will
            # add them to PYTHONPATH and thus make them accessible from within the venv.
            #pythonPackages.numpy
            #pythonPackages.pyserial
            # To compile binaries for the target board
            pkgs.gcc-arm-embedded
            pkgs.stlink
          ] ++ dynamic-libs;

          postVenvCreation = ''
            unset SOURCE_DATE_EPOCH
            pip install -r requirements.txt
          '';

          postShellHook = ''
            # allow pip to install wheels
            unset SOURCE_DATE_EPOCH
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath dynamic-libs}:$LD_LIBRARY_PATH"
            echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" > .env
            echo "⚡ChipWhisperer Environment Loaded!"
          '';
        };
      }
    );
}
