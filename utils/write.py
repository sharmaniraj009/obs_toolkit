

def write_file(file_path, content, binary=False):
    try:
        mode = "wb" if binary else "w"
        with open(file_path, mode) as f:
            f.write(content)
    except Exception as e:
        print(f"[ERROR] Failed to write file: {e}")
        sys.exit(1)