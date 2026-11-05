# AGENTS.md

## Project overview

`ntldd` is a small Windows command-line utility that lists the dynamic
dependencies of a PE module (`.exe`/`.dll`), similar to Unix `ldd`. It also
supports recursive listing, exports, imports, and delayed-load imports.

- Language: C (Windows PE parser).
- Upstream: `https://github.com/roytam1/ntldd` (branch `master`).
- License: GPL-3.0 (`gpl-3.0.txt`).
- Version: `0.2` (`NTLDD_VERSION_MAJOR`/`MINOR` in `libntldd.h`).

The code deliberately supports very old toolchains and Windows versions
(MSVC 6/old SDK, TCC, MinGW, Windows 3.x Win32s, early NT builds, and many
CPU architectures). Preserve that compatibility when editing.

## Repository layout

Tracked source/build files (everything else is generated):

| File | Purpose |
|------|---------|
| `ntldd.c` | Entry point `main()`, CLI parsing, output formatting (`PrintImageLinks`), version/help, text-editor/Win32s handling, Wow64 filesystem redirection setup. |
| `ntlddgui.c` | Win32 GUI (SDI) dependency walker: custom-drawn tree (no comctl32), details/imports/exports panels. Reuses `libntldd`. |
| `libntldd.c` | PE loading (`MyMapAndLoad`), section mapping (`MapPointer`), dependency-tree construction (`BuildDepTree`, `ProcessDep`, `BuildDepTree32or64`), exports/imports/delayed-import parsing. |
| `libntldd.h` | Compatibility shims for old compilers/SDKs, data structures, constants, prototypes. |
| `Makefile` | MinGW cross-build (`x86_64-w64-mingw32-gcc`). |
| `makeldd.cmd` / `makeldd.sh` | MinGW native build scripts. |
| `mk.bat` | MSVC build (`cl`). Pass extra compiler/linker flags as arguments. |
| `mk340.bat` | MSVC build for NT 3.40-era environments (links `ntdll.lib`, `user32.lib`). |
| `mk-axp64.bat` | MSVC build for AXP64. |
| `mk-tcc.bat` | TinyCC build (edit `TCCPATH`). |
| `ntdll.def` | Import library definition for `ntdll.dll` (`NtQuerySystemInformation`, `RtlUnwind`). |
| `README` | User-facing documentation. |

Directories `ARM/`, `ARM64/`, `AXP32/`, `AXP64/`, `IA64/`, `MIPS/`, `PPC/`,
`x64/`, plus `*.obj`, `*.exe`, `*.pdb`, `*.zip` are **build artifacts**
(untracked). Do not edit or commit them.

## Building

All builds produce `ntldd.exe` (and `libntldd.a`/`.obj`).

MinGW (cross, Linux host):

```sh
make
```

MinGW (native Windows, cmd):

```bat
makeldd.cmd
```

MinGW (native, sh):

```sh
sh makeldd.sh
```

MSVC (CLI):

```bat
mk.bat
```

MSVC (GUI):

```bat
mk-gui.bat
```

MSVC with extra flags (e.g. force bundled structs):

```bat
mk.bat /DOLDSDK
```

MSVC for NT 3.40-era:

```bat
mk340.bat
```

TinyCC (edit `TCCPATH` first):

```bat
mk-tcc.bat
```

Notes:
- `OLDSDK` (or old MSVC `< 1200`/`< 1500`, or `__TINYC__`) makes
  `libntldd.h` define its own `IMAGE_*` structures instead of relying on the
  SDK headers. Use `-DOLDSDK` when targeting old SDKs or when the SDK's
  definitions conflict.
- The `Makefile` uses `x86_64-w64-mingw32-gcc`; adjust `CC`/`AR` for other
  hosts/architectures.
- There are no automated tests. Verify manually (see below).

## Running

```text
ntldd [OPTION]... FILE...
```

Important options (many are accepted but not fully implemented):

- `--version` — print version.
- `-v`, `--verbose` — no-op.
- `-u`, `--unused` — no-op.
- `-d`, `--data-relocs` — no-op.
- `-r`, `--function-relocs` — no-op.
- `-R`, `--recursive` — list dependencies recursively (deduplicated).
- `-T`, `--text-editor EDITOR` — write output to `ntldd.txt` and open it in
  `EDITOR` (forced on for Win32s).
- `-D`, `--search-dir DIRS` — extra search directories, `;`-separated.
- `-e`, `--list-exports` — list exports of a single module.
- `-i`, `--list-imports` — list imports.
- `--def-output` — print exports in DEF format.
- `--help` — usage.
- `--` — treat following arguments as file names.

Examples:

```bat
ntldd ntldd.exe
ntldd -R ntldd.exe
ntldd -i -R ntldd.exe
ntldd -e ntldd.exe
ntldd --def-output ntldd.exe
```

On Win32s, output goes to `ntldd.txt`, opened with Notepad, then deleted
after a 5-second delay.

## Architecture

### Data flow

1. `main()` parses arguments, builds a `SearchPaths` (`sp`).
2. Search paths are seeded with the SysWow64 directory (if available) and each
   input file's own directory, plus `-D` directories.
3. For each input file, a `DepTreeElement` child is created and
   `BuildDepTree()` parses the PE and recursively its dependencies.
4. `ClearDepStatus()` clears visited/processed flags.
5. `PrintImageLinks()` prints the tree (recursion controlled by `-R`).

### Key structures (`libntldd.h`)

- `DepTreeElement` — one module node: name, resolved path, mapped address,
  machine type, PE32/PE32+ flag, children, imports, exports, flags
  (`DEPTREE_VISITED`, `DEPTREE_UNRESOLVED`, `DEPTREE_PROCESSED`).
- `ImportTableItem` — one import: original/RVA address, name/ordinal,
  delayed flag, target DLL node, matched export.
- `ExportTableItem` — one export: address, name, ordinal, forwarder string,
  section index.
- `SearchPaths` — array of directories used to locate DLLs.
- `BuildTreeConfig` — parse options and shared state (stack for cycle
  detection, search paths, `on_self`).
- `soff_entry` (internal to `libntldd.c`) — section offset table used to map
  RVAs to file offsets.

### PE parsing notes

- `MyMapAndLoad()` is a ReactOS-derived replacement for `imagehlp`'s
  `MapAndLoad`; it manually opens/maps the file and reads the NT headers.
  On Win32s it redirects `kernel32/user32/gdi32/ntdll/advapi32` lookups to
  `w32scomb.dll` and searches `system\WIN32S`.
- `BuildDepTree()` handles both in-memory (`on_self`) and on-disk modules.
- `BuildDepTree32or64()` parses exports, regular imports, and delay imports
  for both PE32 and PE32+ using `isPE32plus`-aware helpers
  (`thunk_data_u1_function`, `opt_header_get_dd_entry`).
- `ProcessDep()` deduplicates dependencies via `FindDep()` (matched by name
  **and** machine type) and prevents cycles using a stack.
- Imports are matched to exports after parsing (`mapped` field).

### GUI (`ntlddgui`)

- Separate Win32 SDI executable, no `comctl32` (custom-drawn tree + standard
  `USER32` controls: edit, listbox, static, scrollbar).
- Reuses `libntldd` parsing and the same Wow64/search-path logic as the CLI.
- Tree nodes expand/collapse via a `DEPTREE_EXPANDED` flag in
  `DepTreeElement.flags`.
- Build: `make` (MinGW, `ntlddgui.exe` target), `mk-gui.bat` (MSVC),
  `mk-gui-tcc.bat` (TCC).

### Platform-specific behavior

- Win32s detection: `(GetVersion() > 0x80000000) && (LOBYTE(LOWORD(ver)) != 4)`.
  Output is redirected to `ntldd.txt` and opened in Notepad.
- Wow64: when running as a 32-bit process on 64-bit Windows, filesystem
  redirection is disabled and the SysWow64 path is added to search paths.
- Old Windows compatibility: uses `GetModuleHandle` (not `GetModuleHandleExA`),
  `LocalAlloc`/`LocalFree`, avoids `SEC_COMMIT`, etc. Keep these choices.

## Conventions for changes

- Keep the code compiling across MSVC (old), TCC, and MinGW. Prefer C89-style
  declarations at block starts; avoid features unavailable in old MSVC.
- Preserve `#ifdef` shims in `libntldd.h`; gate new SDK-dependent types the
  same way (old MSVC / `__TINYC__` / `OLDSDK`).
- Use Windows APIs (`stricmp`, `MAX_PATH`, `TEXT`), not POSIX equivalents.
- Maintain PE32 and PE32+ support; use the existing helpers for optional-header
  access rather than casting directly.
- Match dependencies by machine type as well as name (see `FindDep`).
- Do not remove the cycle-detection stack logic in `ProcessDep`.
- Output goes through the global `FILE *fp` (`stdout` normally, `ntldd.txt` on
  Win32s). Use `fprintf(fp, ...)`, not `printf`.
- Build artifacts are untracked; do not commit `.obj`/`.exe`/etc.

## Verification

No test suite. After building, smoke-test with:

```bat
ntldd ntldd.exe
ntldd -R ntldd.exe
ntldd -i ntldd.exe
ntldd -e ntldd.exe
ntldd --def-output ntldd.exe
```

Confirm exit code 0 and sensible dependency output. For cross-arch changes,
test on the relevant architecture binaries under `ARM/`, `x64/`, etc. if
available.