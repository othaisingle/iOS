#!/usr/bin/env python3
"""
Script to modify the MinimumOSVersion in an .ipa file.
Compatible with Kali Linux and other systems.
"""

import zipfile
import plistlib
import os
import sys
import shutil
import argparse
from pathlib import Path

def modify_ipa(ipa_path, min_version="15.5", output_suffix="_modified"):
    """
    Modify the MinimumOSVersion in an .ipa file.
    
    Args:
        ipa_path: Path to the .ipa file.
        min_version: iOS version to set (default: 15.5).
        output_suffix: Suffix for the output file.
    
    Returns:
        str: Path to the modified .ipa file.
    """
    
    # Validate input file
    if not os.path.isfile(ipa_path):
        raise FileNotFoundError(f"File not found: {ipa_path}")
    
    # Prepare output filename
    ipa_dir = os.path.dirname(ipa_path)
    ipa_name = os.path.basename(ipa_path)
    name_without_ext = os.path.splitext(ipa_name)[0]
    output_ipa = os.path.join(ipa_dir, f"{name_without_ext}{output_suffix}.ipa")
    
    # Create temporary directory
    temp_dir = Path(f"temp_ipa_{os.getpid()}")
    
    try:
        print(f"Extracting IPA file: {ipa_path}")
        
        # Extract .ipa
        with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # Locate Info.plist in .app folder
        app_dirs = list(temp_dir.glob("Payload/*.app"))
        if not app_dirs:
            raise Exception("No .app folder found inside the IPA file.")
        
        app_path = app_dirs[0]
        info_plist_path = app_path / "Info.plist"
        
        if not info_plist_path.exists():
            raise Exception("Info.plist not found.")
        
        print(f"Found Info.plist at: {info_plist_path}")
        
        # Read Info.plist
        with open(info_plist_path, 'rb') as f:
            try:
                plist_data = plistlib.load(f)
            except Exception:
                f.seek(0)
                try:
                    plist_data = plistlib.loads(f.read())
                except Exception as e:
                    raise Exception(f"Failed to read Info.plist: {e}")
        
        # Modify MinimumOSVersion
        old_version = plist_data.get('MinimumOSVersion', 'Not found')
        plist_data['MinimumOSVersion'] = min_version
        
        print(f"MinimumOSVersion changed from {old_version} to {min_version}")
        
        # Save Info.plist
        with open(info_plist_path, 'wb') as f:
            plistlib.dump(plist_data, f)
        
        # Recreate the .ipa file
        print(f"Creating new IPA file: {output_ipa}")
        with zipfile.ZipFile(output_ipa, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arcname)
        
        print(f"Process completed successfully. Output file: {output_ipa}")
        return output_ipa
        
    finally:
        # Clean up temporary directory
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

def main():
    parser = argparse.ArgumentParser(description='Modify MinimumOSVersion in an IPA file.')
    parser.add_argument('ipa_file', help='Path to the IPA file.')
    parser.add_argument('--version', '-v', default='15.5', 
                        help='Target iOS version (default: 15.5).')
    parser.add_argument('--output', '-o', 
                        help='Output file name (if not specified, "_modified" will be appended).')
    
    args = parser.parse_args()
    
    try:
        output_suffix = "_modified"
        if args.output:
            output_ipa = args.output
            if not output_ipa.endswith('.ipa'):
                output_ipa += '.ipa'
        else:
            output_ipa = None
        
        result = modify_ipa(
            ipa_path=args.ipa_file,
            min_version=args.version,
            output_suffix=output_suffix
        )
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
