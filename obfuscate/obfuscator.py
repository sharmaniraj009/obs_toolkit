import base64
import sys
from utils import read
from utils import write


def base64_obfuscate(content):
    return base64.b64encode(content.encode()).decode()

def xor_obfuscate(content, key):
    if not key:
        print("[ERROR] XOR key is missing. Use --key parameter when using XOR method.")
        sys.exit(1)
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(content))


def process_obfuscation(file_path, methods, binary=False, key=None):
    content = read.read_file(file_path, binary)
    for method in methods:
        if method == "base64":
            content = base64_obfuscate(content) if not binary else base64.b64encode(content).decode()
        elif method == "xor":
            content = xor_obfuscate(content, key)
    output_file = f"{file_path}.obf"
    write.write_file(output_file, content, binary)
    print(f"[SUCCESS] Obfuscated file saved as {output_file}")