import base64

def base64_obfuscate(content):
    return base64.b64encode(content.encode()).decode()

def xor_obfuscate(content, key="secret"):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(content))

def process(file_path, methods):
    with open(file_path, "r") as f:
        content = f.read()

    print(f"[INFO] Original Content: {content}")
    
    for method in methods:
        print(f"[INFO] Applying {method} obfuscation")
        if method == "base64":
            content = base64_obfuscate(content)
        elif method == "xor":
            content = xor_obfuscate(content)
        else:
            print(f"[WARNING] Unknown obfuscation method '{method}', skipping.")

    output_file = f"{file_path}.obf"
    with open(output_file, "w") as f:
        f.write(content)
    print(f"[SUCCESS] Obfuscated file saved as {output_file}")
