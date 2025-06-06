import hashlib
import os
import json
import argparse

# === CONFIG ===
HASH_ALGORITHM = 'sha256'
INTEGRITY_FILE = 'file_hashes.json'

def get_file_hash(file_path, algorithm=HASH_ALGORITHM):
    """Calculate hash of a given file."""
    hash_func = hashlib.new(algorithm)
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def scan_directory(directory):
    """Scan and hash all files in a directory."""
    hashes = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            file_hash = get_file_hash(file_path)
            if file_hash:
                relative_path = os.path.relpath(file_path, directory)
                hashes[relative_path] = file_hash
    return hashes

def save_hashes(hashes, file_path=INTEGRITY_FILE):
    with open(file_path, 'w') as f:
        json.dump(hashes, f, indent=4)

def load_hashes(file_path=INTEGRITY_FILE):
    if not os.path.exists(file_path):
        return {}
    with open(file_path, 'r') as f:
        return json.load(f)

def check_integrity(current_hashes, original_hashes):
    """Compare hash maps and detect changes."""
    modified = []
    added = []
    deleted = []

    for path, hash_val in current_hashes.items():
        if path not in original_hashes:
            added.append(path)
        elif original_hashes[path] != hash_val:
            modified.append(path)

    for path in original_hashes:
        if path not in current_hashes:
            deleted.append(path)

    return added, modified, deleted

def main():
    parser = argparse.ArgumentParser(description='File Integrity Checker')
    parser.add_argument('directory', help='Directory to monitor')
    parser.add_argument('--init', action='store_true', help='Initialize hash database')

    args = parser.parse_args()
    dir_path = args.directory

    if not os.path.isdir(dir_path):
        print("Invalid directory")
        return

    current_hashes = scan_directory(dir_path)

    if args.init:
        save_hashes(current_hashes)
        print("Initialization complete. Hashes saved.")
    else:
        original_hashes = load_hashes()
        added, modified, deleted = check_integrity(current_hashes, original_hashes)

        if not (added or modified or deleted):
            print("No changes detected.")
        else:
            if added:
                print(f"Added files:\n - " + "\n - ".join(added))
            if modified:
                print(f"Modified files:\n - " + "\n - ".join(modified))
            if deleted:
                print(f"Deleted files:\n - " + "\n - ".join(deleted))

if __name__ == '__main__':
    main()
