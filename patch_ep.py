import argparse
import pefile
import sys
import os

# Target strings to be removed (overwritten with null bytes)
# Important: Define as bytes objects (b'...')
TARGET_STRINGS = [
    b"$Id: UPX ",
    b"UPX!",
    b"UPX ",      # Added: Another UPX marker
    b"INFO: UPX", # Added: UPX info string
    b"This file is packed with the UPX executable packer", # Added: UPX description
    b"http://upx.sf.net" # Added: UPX website reference
]

def patch_pe_file(input_path, output_path):
    """
    Patches a PE file to remove specific detection signatures:
    1. Overwrites the first byte at the Entry Point (EP) with a NOP (0x90).
    2. Searches for defined string signatures (TARGET_STRINGS) and
       overwrites them with null bytes.
    3. Modifies section names that might identify UPX packing.

    Args:
        input_path (str): Path to the input PE file.
        output_path (str): Path where the patched PE file will be saved.

    Returns:
        bool: True if patching was successful, False otherwise.
    """
    try:
        print(f"[/] Loading PE file: {input_path}")
        # Loading with keep_file_alignment=True can sometimes help maintain the structure
        pe = pefile.PE(input_path, fast_load=False) # fast_load=False is safer for modifications

        # --- 1. Entry Point Patching ---
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print(f"[+] Entry Point RVA: 0x{ep_rva:X}")
        ep_offset = pe.get_offset_from_rva(ep_rva)
        if ep_offset is None:
             print(f"[x] Error: Could not find file offset for EP RVA 0x{ep_rva:X}.")
             # Don't necessarily abort, we might still patch strings
        else:
            print(f"[+] Entry Point File Offset: 0x{ep_offset:X}")
            try:
                original_byte_data = pe.get_data(ep_rva, 1)
                if original_byte_data:
                     original_byte = original_byte_data[0]
                     print(f"[+] Original byte at EP: 0x{original_byte:02X}")
                     patch_byte = b'\x90' # NOP
                     print(f"[/] Patching byte at offset 0x{ep_offset:X} with 0x{patch_byte[0]:02X} (NOP)")
                     pe.set_bytes_at_offset(ep_offset, patch_byte)
                else:
                    print(f"[-] Warning: Could not read original byte at EP (Offset 0x{ep_offset:X}).")
            except Exception as e_ep:
                 print(f"[-] Warning: Error reading/patching EP byte: {e_ep}")


        # --- 2. String Signature Patching ---
        print("[/] Searching for string signatures to overwrite...")
        file_data = pe.__data__ # Access to the raw file data
        strings_patched_count = 0

        for target_string in TARGET_STRINGS:
            print(f"[/] Searching for: {target_string!r}")
            current_offset = 0
            while True:
                # Search for the string in the rest of the data
                found_offset = file_data.find(target_string, current_offset)

                if found_offset == -1:
                    # String not found anymore
                    break

                print(f"[+] String {target_string!r} found at file offset: 0x{found_offset:X}")

                # Create null bytes with the length of the found string
                string_len = len(target_string)
                null_bytes = b'\x00' * string_len

                # Patch the data at this offset
                print(f"[/] Overwriting {string_len} bytes at offset 0x{found_offset:X} with null bytes.")
                try:
                    pe.set_bytes_at_offset(found_offset, null_bytes)
                    strings_patched_count += 1
                except Exception as e_str:
                    print(f"[-] Warning: Error overwriting string at offset 0x{found_offset:X}: {e_str}")

                # Set the starting point for the next search for this string
                current_offset = found_offset + 1 # Continue search from the next byte

        if strings_patched_count == 0:
            print("[-] None of the target string signatures found in the file.")
        else:
            print(f"[+] {strings_patched_count} string occurrences marked for overwriting.")

        # --- 3. UPX Section Name Patching ---
        # Added: Clean up UPX section names
        upx_section_names = [b"UPX0", b"UPX1", b"UPX2", b"UPX3"]
        sections_renamed = 0
        
        print("[/] Checking for UPX section names...")
        for section in pe.sections:
            original_name = section.Name.rstrip(b'\x00')
            for upx_name in upx_section_names:
                if original_name == upx_name:
                    # Rename the section to a neutral name
                    new_name = b".text" if upx_name == b"UPX0" else b".data"
                    # Ensure the name is padded to 8 bytes as required by PE format
                    new_name = new_name.ljust(8, b'\x00')
                    print(f"[+] Renaming section {original_name!r} to {new_name!r}")
                    section.Name = new_name
                    sections_renamed += 1
        
        if sections_renamed > 0:
            print(f"[+] {sections_renamed} UPX section names renamed.")
        else:
            print("[-] No UPX section names found.")

        # --- 4. Write the modified file ---
        print(f"[/] Writing patched file to: {output_path}")
        # Use a method that tries to preserve the structure
        pe.write(filename=output_path)

        print(f"[+] Patching completed. Patched file saved as: {output_path}")
        return True

    except pefile.PEFormatError as e:
        print(f"[x] Error parsing the PE file: {e}")
        return False
    except FileNotFoundError:
        print(f"[x] Error: Input file not found: {input_path}")
        return False
    except Exception as e:
        print(f"[x] An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc() # Print more details for unexpected errors
        return False
    finally:
        # Ensure the PE file is closed
        if 'pe' in locals() and pe:
            pe.close()

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description='UPX Patcher - Cleans UPX signatures from PE files')
    parser.add_argument('input_file', help='Path to the executable file to process')
    parser.add_argument('-o', '--output', help='Custom output file path (default: inputfile_patched.ext)')
    
    # Parse arguments
    args = parser.parse_args()
    
    input_file = args.input_file
    
    if not os.path.isfile(input_file):
        print(f"[x] Error: Input file not found or is not a file: {input_file}")
        sys.exit(1)
    
    # Create output filename
    if args.output:
        output_file = args.output
        print(f"[/] Custom output path specified: {output_file}")
    else:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_patched{ext}"
    
    # Start patching process
    patch_pe_file(input_file, output_file)

