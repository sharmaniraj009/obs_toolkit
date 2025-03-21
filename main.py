import argparse
import os
import sys
from steganography import steganography
from obfuscate.obfuscator import process_obfuscation
from deobfuscate.deobfuscator import process_deobfuscation

def main():
    parser = argparse.ArgumentParser(description="Obfuscation & Steganography Toolkit")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # ========== OBFUSCATION ==========
    obf_parser = subparsers.add_parser("obfuscate", help="Apply obfuscation techniques")
    obf_parser.add_argument("file", type=str, help="Path to the input file")
    obf_parser.add_argument("--methods", type=str, required=True, help="Comma-separated obfuscation methods (e.g., base64,xor,steg-image,whitespace)")
    obf_parser.add_argument("--binary", action="store_true", help="Process file as binary")
    obf_parser.add_argument("--image", type=str, help="Path to input image (for steg-image)")
    obf_parser.add_argument("--output", type=str, help="Output file (for steg-image)")
    
    # ========== DEOBFUSCATION ==========
    deobf_parser = subparsers.add_parser("deobfuscate", help="Reverse obfuscation techniques")
    deobf_parser.add_argument("file", type=str, help="Path to the input file")
    deobf_parser.add_argument("--methods", type=str, required=True, help="Comma-separated deobfuscation methods (in reverse order)")
    deobf_parser.add_argument("--binary", action="store_true", help="Process file as binary")
    deobf_parser.add_argument("--image", type=str, help="Path to steg-image file for extraction")

    args = parser.parse_args()

    if args.mode == "obfuscate":
        if "steg-image" in args.methods:
            if not args.image or not args.output:
                print("[ERROR] --image and --output parameters are required for steg-image.")
                sys.exit(1)
            content = open(args.file, "r").read()
            steganography.encode_image(args.image, content, args.output)
        elif "whitespace" in args.methods:
            content = open(args.file, "r").read()
            encoded_content = steganography.encode_whitespace(content)
            with open(f"{args.file}.steg", "w", encoding="utf-8") as f:
                f.write(encoded_content)
            print(f"[SUCCESS] Data hidden using whitespace steganography in {args.file}.steg")
        else:
            methods = args.methods.split(",")
            process_obfuscation(args.file, methods, args.binary)

    elif args.mode == "deobfuscate":
        if "steg-image" in args.methods:
            if not args.image:
                print("[ERROR] --image parameter is required for steg-image.")
                sys.exit(1)
            message = steganography.decode_image(args.image)
            print(f"[DECODED MESSAGE]: {message}")
        elif "whitespace" in args.methods:
            encoded_content = open(args.file, "r", encoding="utf-8").read()
            decoded_message = steganography.decode_whitespace(encoded_content)
            print(f"[DECODED MESSAGE]: {decoded_message}")
        else:
            methods = args.methods.split(",")
            process_deobfuscation(args.file, methods, args.binary)

if __name__ == "__main__":
    main()
