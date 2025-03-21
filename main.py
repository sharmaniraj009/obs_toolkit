import argparse
import os
from obfuscate import obfuscator
from deobfuscate import deobfuscator

def main():
    parser = argparse.ArgumentParser(description="Obfuscation & Deobfuscation Toolkit")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    obf_parser = subparsers.add_parser("obfuscate", help="Apply obfuscation techniques")
    obf_parser.add_argument("file", type=str, help="Path to the input file")
    obf_parser.add_argument("--methods", type=str, required=True, 
                            help="Comma-separated obfuscation methods (e.g., base64,xor)")

    deobf_parser = subparsers.add_parser("deobfuscate", help="Reverse obfuscation techniques")
    deobf_parser.add_argument("file", type=str, help="Path to the input file")
    deobf_parser.add_argument("--methods", type=str, required=True, 
                              help="Comma-separated deobfuscation methods (in reverse order)")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[ERROR] File '{args.file}' not found.")
        return

    methods = args.methods.split(",")

    if args.mode == "obfuscate":
        process_obfuscation(args.file, methods)
    elif args.mode == "deobfuscate":
        process_deobfuscation(args.file, methods)

if __name__ == "__main__":
    main()
