import base64
from utils import read
from utils import write



def base64_deobfuscate(content):
    try:
        return base64.b64decode(content).decode()
    except Exception:
        print("Error: Base64 decoding failed. Check the encoding order.")
        return None


def xor_deobfuscate(content, key):
    if not key:
        print("[ERROR] XOR key is missing.")
        sys.exit(1)
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(content))

def process_deobfuscation(file_path, methods, binary=False, key=None):
    content = read.read_file(file_path, binary)
    for method in reversed(methods):
        if method == "base64":
            content = base64_deobfuscate(content) if not binary else base64.b64decode(content)
        elif method == "xor":
            content = xor_deobfuscate(content, key)
    output_file = f"{file_path}.deobf"
    write.write_file(output_file, content, binary)
    print(f"[SUCCESS] Deobfuscated file saved as {output_file}")