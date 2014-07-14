with import <nixpkgs> { };

stdenv.mkDerivation {
  name = "aefs";

  src = if lib.inNixShell then null else ./.;

  postUnpack = ''
    # Clean up when building from a working tree.
    (cd $sourceRoot && (git ls-files -o | xargs -r rm -v))
  '';

  preConfigure = ''
    autoreconf
  '';

  buildInputs = [ fuse git autoreconfHook ];

  NIX_CFLAGS_COMPILE = "-Wno-pointer-sign -Wunused-variable";

  enableParallelBuilding = true;
}
