import base64

def process(file):
    with open(file, 'r') as f:
        data = f.read()

    offuscated_content = base64.b64encode(data.encode()).decode()

    with open(f"{file_path}.obf", "w") as f:
        f.write(offuscated_content)

    print(f"Obfuscated content saved to {file_path}.obf")