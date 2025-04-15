# UPX Patcher

UPX Patcher is a Python tool for patching PE (Portable Executable) files by removing specific detection signatures associated with UPX (Ultimate Packer for eXecutables). This tool modifies section names that may indicate UPX packing and provides a straightforward way to create patched versions of executables.

## Features
- Overwrites specific detection signatures with null bytes.
- Renames UPX section names to neutral names.
- Preserves the structure of the original PE file.

## Installation
To install the required dependencies, run:
```
pip install -r requirements.txt
```

## Usage
To patch a PE file, run the following command:
```
python src/patch_ep.py <path_to_executable_file>
```
The patched file will be saved with a "_patched" suffix in the same directory.
