import base64

def process(file):

    with open(file, 'r') as f:
        data = f.read()
    
    try:
        deobfuscated_content = base64.b64decode(data).decode()
        output_file = file.replace('.obf', '.deobf')
        with open(output_file, 'w') as f:
            f.write(deobfuscated_content)
        print(f"Deobfuscated content saved to {output_file}")
    except Exception:
        print("Error: Invalid input file")


