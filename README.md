packf

Pack many text files into one single text file — NOT an archive.

packf is a fast, cross-platform command-line tool written in C++17 that combines multiple text files into a single, readable text file.

It recursively scans directories, detects and skips binary files, handles multiple text encodings, normalizes line endings, and preserves file order. It is designed to make collecting source code, configuration files, documentation, and project contents easy.

Features
Fast & Multithreaded: Processes files concurrently while preserving their original output order.
Cross-platform: Supports Linux, macOS, and Windows.
Recursive scanning: Automatically scans directories and their subdirectories.
Smart file detection: Detects binary files and skips them automatically.
Encoding support:
UTF-8
UTF-8 with BOM
UTF-16 LE / BE
Windows-1252
Windows-1254
ISO-8859-1 (Latin-1)
ISO-8859-9 (Latin-5)
Line ending control: Keep original, convert to LF, or convert to CRLF.
Flexible filtering: Include or exclude files using extensions and glob patterns.
Natural sorting: Sorts file2.txt before file10.txt.
Custom headers: Add customizable file headers with path, filename, index, and size placeholders.
External converters: Supports external commands for formats such as PDF and DOCX.
Symlink support: Optionally follows symbolic links.
Memory-aware pipeline: Uses a soft 256 MiB in-flight buffer budget for multithreaded processing.
Safe output: Writes to a temporary file before replacing the destination.
Dry-run mode: List files that would be processed without creating an output file.
Requirements
C++17 compatible compiler
Standard C++ threading support
GCC 8 may require the additional stdc++fs library.
Build
Linux / macOS
bash
g++ -O2 -std=c++17 -pthread -o packf packf.cpp


For GCC 8:

bash
g++ -O2 -std=c++17 -pthread -o packf packf.cpp -lstdc++fs

Windows (MinGW)
bash
g++ -O2 -std=c++17 -o packf.exe packf.cpp -lshell32

Windows (MSVC)
bat
cl /O2 /std:c++17 /EHsc packf.cpp shell32.lib

Usage
bash
packf [OPTIONS] [PATH...]


PATH can be either a file or a directory.

Directories are scanned recursively by default.
If no path is provided, the current directory is scanned.
Explicitly specified files are processed in the order given.
Extension and glob filters apply to files discovered during directory scanning.
Examples
Pack the current directory
bash
packf


Creates packed.txt containing all detected text files under the current directory.

Pack selected directories
bash
packf src include -o all.txt

Pack only C/C++ header files
bash
packf -e h,hpp -o headers.txt include/

Merge specific files in a defined order
bash
packf -o notes.md README.md TODO.md CHANGELOG.md

Exclude build directories
bash
packf -X build -X node_modules -o project.txt .

Include only source files
bash
packf -e c,cpp,h,hpp,py,js,ts -o source.txt .

Write output to stdout
bash
packf -o - src/ | wc -c

Preview files without packing
bash
packf --list src/

Use multiple threads
bash
packf -j 8 -o packed.txt .

Convert line endings to LF
bash
packf --eol lf -o output.txt .

Disable file headers
bash
packf -N -o output.txt .

Convert PDF and DOCX files
bash
packf \
  -F 'pdf=pdftotext -layout {} -' \
  -F 'docx=pandoc -t plain' \
  -o documents.txt .


Requires pdftotext and pandoc to be installed.

Command-line Options
Output
Option	Description
-o, --output FILE	Output file. Default: packed.txt. Use - for stdout.
-H, --header FMT	Custom header format.
-N, --no-header	Disable file headers.
-B, --no-blank	Remove blank lines between files.
--eol MODE	Line ending mode: keep, lf, crlf.
File Selection
Option	Description
-e, --ext LIST	Include only specified extensions.
-x, --exclude-ext LIST	Exclude specified extensions.
-i, --include GLOB	Include matching paths (repeatable).
-X, --exclude GLOB	Exclude matching files/directories (repeatable).
-n, --no-recurse	Disable recursive directory scanning.
-a, --all	Include hidden files and directories.
-L, --follow-symlinks	Follow symbolic links.
-S, --sort MODE	Sorting: natural, name, none.
-m, --max-size SIZE	Maximum file size. Default: 32M. Use 0 for unlimited.
Encoding & Conversion
Option	Description
-E, --encoding ENC	Encoding for invalid UTF-8: cp1252, cp1254, latin1, iso-8859-9, raw, skip.
-F, --filter EXT=CMD	External converter for a specific extension (repeatable).
Miscellaneous
Option	Description
-j, --jobs N	Number of worker threads. Default: CPU count, maximum 16.
-l, --list	List files without packing.
-v, --verbose	Show per-file processing information.
-q, --quiet	Suppress summary output.
-h, --help	Display help.
-V, --version	Display version.
Custom Headers

By default, packf automatically selects a comment style based on the output file extension.

Examples:

text
// ===== src/main.cpp =====

text
# ===== scripts/build.py =====

text
<!-- ===== index.html ===== -->


Custom headers can be defined using placeholders:

Placeholder	Meaning
%p	Full displayed file path
%n	File name
%i	File index
%s	File size in bytes
%%	Literal %

Example:

bash
packf -H '// FILE: %n | SIZE: %s bytes' -o output.cpp .


Newline and tab escapes (\n, \t) are supported.

Glob Patterns

The following glob patterns are supported:

Pattern	Meaning
*	Matches any sequence except /.
**	Matches any sequence, including /.
**/	Matches zero or more directories.
?	Matches a single character except /.
[a-z]	Matches a character in a range.
[!a-z]	Matches a character outside a range.

Examples:

bash
# Exclude all test files
packf -X '**/test_*' .

# Include only files inside src directories
packf -i 'src/**/*.cpp' .

# Exclude build and cache directories
packf -X build -X '**/__pycache__' .

Encoding Behavior

packf automatically detects common text formats:

UTF-8 is preserved.
UTF-8 BOM is removed.
UTF-16 LE and BE are converted to UTF-8.
Invalid UTF-8 is handled according to --encoding.
Binary files are skipped.

The default legacy encoding is Windows-1252.

For Turkish Windows-1254 files:

bash
packf -E cp1254 -o output.txt .


To skip files that are not valid UTF-8:

bash
packf -E skip -o output.txt .


To copy invalid UTF-8 bytes without conversion:

bash
packf -E raw -o output.txt .

Performance

packf uses a multithreaded producer-consumer pipeline:

Multiple files can be processed simultaneously.
Results are written in the original collection order.
A bounded in-flight buffer budget helps control memory usage.
File processing and output writing are separated.
Large files are skipped according to the configured size limit.

The default worker count is based on the available CPU cores, capped at 16.

Output Safety

When writing to a regular output file, packf first writes to a temporary file:

text
packed.txt.packf-tmp


After successful processing, the temporary file replaces the destination.

This helps prevent an incomplete output from replacing an existing file if processing or writing fails.

Exit Codes
Code	Meaning
0	Successful execution.
1	No text files packed or one or more processing errors occurred.
2	Command-line, output, or fatal error.
130	Interrupted with SIGINT on supported Unix-like systems.
Version

Current version: 1.0.0

License
MIT



packf — Simple, fast, and reliable text file collection.
