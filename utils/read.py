def read_file(file_path, binary=False):
    try:
        mode = "rb" if binary else "r"
        with open(file_path, mode) as f:
            return f.read()
    except Exception as e:
        print(f"[ERROR] Failed to read file: {e}")
        sys.exit(1)

