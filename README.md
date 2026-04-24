# GolangAnalyzerExtension
The GolangAnalyzerExtension facilitates the analysis of Golang binaries using Ghidra.
It supports go1.6 through go1.26.

## Fork hotfix note
Added support improvements for recovering function metadata from .pclntab in stripped Go binaries (for example binaries built with -ldflags="-s -w").

What was changed:
- Improved Go 1.18+ function parsing to handle cases where PcHeader textStart is zero by falling back to moduledata.text.
- Added a second fallback to .text section start when moduledata is unavailable.
- Relaxed function entry consistency checks to accept both absolute functab addresses and text-relative functab offsets.
- Improved stripped-binary handling by creating/disassembling functions from pclntab entries when functions are not already materialized.
- This improves function name recovery from pclntab metadata when symbols are stripped.

Additional fork hotfix for source links:
- Standard library source links now use the identified Go version when formatting `github.com/golang/go` URLs.
- Blob refs like `go1.20beta1` are normalized to `go1.20` for GitHub, because some beta tags are not available and return 404.
- This prevents broken links such as `.../blob/go1.20beta1/...` while keeping valid tags (for example `go1.20rc1`) unchanged.

## Features
This Ghidra plugin provides the following features for analyzing Golang binaries:

- Identification of the Golang version
- Renaming of functions
- Correction of function arguments
- Documentation of source file names and line numbers in comments
- Integration of custom data types into the Data Type Manager
- String searching within the binary
- Clickable URLs to the Golang source code

Refer to the images below for a visual demonstration.

<img src="img/demo.png">

<img src="img/demo.gif">

<img src="img/go_link.png">

## Usage
1. Download the latest release
2. Launch Ghidra
3. Go to `File -> Install Extensions... -> Add extension -> Select zip file`
4. Enable the `GolangAnalyzerExtension` by checking its checkbox
5. Restart Ghidra to apply changes
6. Begin analyzing your Golang binary
