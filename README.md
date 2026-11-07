# packf

`packf` is a high-performance, multi-threaded C++17 command-line utility designed to pack multiple text files into a single text file.

**Note:** This tool is **not** an archiving utility (like zip, tar, or 7z). Its purpose is to concatenate project source code, documentation, or text notes into a single formatted file—complete with customizable file headers and clean separators—ideal for Large Language Model (LLM) prompts, code reviews, or unified textual analysis.

## Features

* **Multi-threaded Pipeline:** Uses a worker thread pool to perform file discovery, reading, text validation, and encoding conversion concurrently.
* **Automatic Binary Detection:** Inspects file content to detect and skip binary files, oversized items, or non-regular files to prevent output corruption.
* **Smart Encoding Support:**
  * Automatically detects and converts UTF-8 (with or without BOM) and UTF-16 (LE/BE) into clean UTF-8.
  * Supports legacy single-byte encodings (`cp1252`, `cp1254`, `latin1`, `iso-8859-9`) for non-UTF-8 files, with options to process raw bytes or skip invalid files.
* **Language-Aware Headers:** Automatically formats file header comments according to the output file extension (e.g., `//` for C/C++, `#` for Python/Bash, `--` for SQL, `<!-- -->` for HTML/XML). Supports format specifiers like `%p` (path), `%n` (filename), `%s` (size), and `%i` (file index).
* **Flexible Selection & Filtering:** Filter by file extensions, glob patterns (`-i` / `-X`), toggle hidden files (`-a`), or follow symbolic links (`-L`).
* **External Process Filters:** Pass specific file extensions through external command-line utilities (e.g., convert `.docx` via `pandoc` or `.pdf` via `pdftotext`) before merging.

## Building

`packf` is written in standard C++17 without external library dependencies.

### Linux / macOS (GCC / Clang)

```bash
g++ -O2 -std=c++17 -pthread -o packf packf.cpp
# Note: GCC 8 additionally requires -lstdc++fs
```

### Windows (MinGW)

```cmd
g++ -O2 -std=c++17 -o packf.exe packf.cpp -lshell32
```

### Windows (MSVC)

```cmd
cl /O2 /std:c++17 /EHsc packf.cpp shell32.lib
```

## Usage

```text
packf [OPTIONS] [PATH...]
```

If no `PATH` is provided, `packf` recursively scans the current working directory (`.`). Files explicitly specified on the command line are always included in the exact order given.

### Command-Line Options

#### Output & Formatting

| Option | Description |
| :--- | :--- |
| `-o, --output FILE` | Output file path (use `-` for stdout). Default: `packed.txt` |
| `-H, --header FMT` | Custom header format string. Variables: `%p` (path), `%n` (name), `%i` (index), `%s` (bytes). Default: `===== %p =====` (comment-adapted) |
| `-N, --no-header` | Disable file header lines |
| `-B, --no-blank` | Do not insert blank lines between packed files |
| `--eol MODE` | Line ending normalization: `keep` (default), `lf`, or `crlf` |

#### File Selection & Filtering

| Option | Description |
| :--- | :--- |
| `-e, --ext LIST` | Comma-separated list of extensions to include (e.g., `-e h,hpp,cpp`) |
| `-x, --exclude-ext LIST` | Comma-separated list of extensions to skip |
| `-i, --include GLOB` | Only include paths matching the glob pattern (repeatable) |
| `-X, --exclude GLOB` | Exclude paths matching the glob pattern (repeatable, e.g., `-X build -X '**/test_*'`) |
| `-n, --no-recurse` | Disable recursive directory scanning |
| `-a, --all` | Include hidden files and directories (starting with `.`) |
| `-L, --follow-symlinks` | Follow symbolic links during directory traversal |
| `-S, --sort MODE` | Sorting strategy: `natural` (default, e.g. `file2` < `file10`), `name`, or `none` |
| `-m, --max-size SIZE` | Skip files larger than `SIZE` (e.g., `500k`, `64M`, `2G`; `0` = unlimited). Default: `32M` |

#### Text Processing & External Filters

| Option | Description |
| :--- | :--- |
| `-E, --encoding ENC` | Fallback encoding for non-UTF-8 text: `cp1252` (default), `cp1254`, `latin1`, `iso-8859-9`, `raw`, or `skip` |
| `-F, --filter EXT=CMD` | Pipe files with extension `EXT` through `CMD` (e.g., `-F 'docx=pandoc -t plain'`) |

#### General

| Option | Description |
| :--- | :--- |
| `-j, --jobs N` | Number of worker threads (default: CPU cores, capped at 16) |
| `-l, --list` | Dry-run mode: list files that would be packed without generating output |
| `-v, --verbose` | Enable verbose per-file progress reporting |
| `-q, --quiet` | Suppress summary report |
| `-h, --help` | Display help message and exit |
| `-V, --version` | Display version information and exit |

## Examples

* Pack all text files in the current directory into `packed.txt`:
  ```bash
  packf
  ```

* Pack C/C++ source and header files into `all_code.cpp`:
  ```bash
  packf -e c,cpp,h,hpp -o all_code.cpp src/ include/
  ```

* Combine specific header files into a single bundle:
  ```bash
  packf -o merged.h include/a.h include/b.h
  ```

* Ignore build folders and node_modules while streaming output directly to `wc`:
  ```bash
  packf -X node_modules -X build -e c,cpp,h -o - . | wc -c
  ```

* Extract text from PDF and DOCX files using external filters:
  ```bash
  packf -F "pdf=pdftotext -layout {} -" -F "docx=pandoc -t plain" -o output.txt docs/
  ```