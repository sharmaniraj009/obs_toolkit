import base64

def base64_deobfuscate(content):
    try:
        return base64.b64decode(content).decode()
    except Exception:
        print("Error: Base64 decoding failed. Check the encoding order.")
        return None


def xor_deobfuscate(content, key="secret"):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(content))

def process(file_path, methods):
    with open(file_path, "r") as f:
        content = f.read()

    print(f"[INFO] Obfuscated Content: {content}")
    
    for method in reversed(methods):
        print(f"[INFO] Applying {method} deobfuscation")
        if method == "base64":
            content = base64_deobfuscate(content)
        elif method == "xor":
            content = xor_deobfuscate(content)
        else:
            print(f"[WARNING] Unknown deobfuscation method '{method}', skipping.")

        if content is None:
            print("[ERROR] Deobfuscation failed. Exiting...")
            return

    output_file = f"{file_path}.deobf"
    with open(output_file, "w") as f:
        f.write(content)
    print(f"[SUCCESS] Deobfuscated file saved as {output_file}")