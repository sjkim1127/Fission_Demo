# Runtime Guide (Core Package)

## Quick Start

1. Open a terminal in the extracted package root.
2. Run:

```powershell
./bin/fission_cli.exe --info <path-to-your-binary>
./bin/fission_cli.exe --funcs <path-to-your-binary>
```

## Decompilation

`--decomp` requires native runtime files (`decomp.dll`, `zlib*.dll`) and works best with signatures installed.

```powershell
./bin/fission_cli.exe --decomp <addr> <path-to-your-binary>
```

## Signatures (Optional but recommended)

If you have `fission-demo-signatures-full-*.zip`, extract it so this folder exists next to package root:

```text
./signatures
```

This improves function identification and type information quality.
