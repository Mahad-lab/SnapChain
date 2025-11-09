import os
import threading
import hashlib
import mmh3  # pip install mmh3
from datetime import datetime
from mss import mss
from pynput import mouse

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
SAVE_DIR = "./screenshots"
HASHES_FILE = "./hashes.txt"
FILE_PREFIX = "snapshot"
CAPTURE_REGION = None  # None = full screen

if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

stop_listener = threading.Event()

# ----------------------------------------------------------------------
# Helper: Time
# ----------------------------------------------------------------------
def now_ms():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")[:-3]

# ----------------------------------------------------------------------
# Hashing Functions
# ----------------------------------------------------------------------
def file_sha256(filepath: str, chunk_size: int = 8192) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()

def file_murmur3(filepath: str, seed: int = 42) -> str:
    with open(filepath, "rb") as f:
        data = f.read()
    # return format(mmh3.hash_bytes(data, seed).hex(), 'x')  # 32-char hex
    hash_bytes = mmh3.hash_bytes(data, seed)
    return hash_bytes.hex()  # ← correct: convert bytes → hex string
# ----------------------------------------------------------------------
# Blockchain Chain Logic
# ----------------------------------------------------------------------
PREV_HASH_FILE = "./prev_record_hash.txt"  # stores last record's full hash

def get_previous_record_hash() -> str:
    """Read the hash of the last record (for chain linking)."""
    if not os.path.exists(PREV_HASH_FILE):
        return "0" * 64  # Genesis block: 64 zeros
    with open(PREV_HASH_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()

def update_previous_record_hash(new_record_hash: str):
    """Save the current record hash as previous for the next one."""
    with open(PREV_HASH_FILE, "w", encoding="utf-8") as f:
        f.write(new_record_hash)

# ----------------------------------------------------------------------
# Append Record with Chain
# ----------------------------------------------------------------------
def append_block_to_chain(filename: str, sha256_hash: str, murmur_hash: str):
    """Append a new 'block' to hashes.txt with previous hash link."""
    prev_hash = get_previous_record_hash()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    rel_path = os.path.relpath(filename, start=os.path.dirname(HASHES_FILE))

    # Full record line (this becomes the "block")
    record = f"{timestamp}|{rel_path}|{sha256_hash}|{murmur_hash}|{prev_hash}"
    record_hash = hashlib.sha256(record.encode("utf-8")).hexdigest()

    # Append to chain file
    with open(HASHES_FILE, "a", encoding="utf-8") as hf:
        line = f"{timestamp} | {rel_path} | {sha256_hash} | {murmur_hash} | prev:{prev_hash} | this:{record_hash}\n"
        hf.write(line)

    # Update previous hash for next block
    update_previous_record_hash(record_hash)

    print(f"Block added | SHA256: {sha256_hash[:8]}... | Murmur: {murmur_hash[:8]}... | Chain: {record_hash[:8]}...")

# ----------------------------------------------------------------------
# Screenshot + Hash + Chain
# ----------------------------------------------------------------------
def capture_screen(x=None, y=None):
    with mss() as sct:
        if CAPTURE_REGION is None:
            filename = f"{SAVE_DIR}/{FILE_PREFIX}_{now_ms()}.png"
            sct.shot(mon=1, output=filename)
            print(f"Saved full screen: {filename}")
        else:
            region = CAPTURE_REGION.copy()
            if region.get("center") and x is not None and y is not None:
                hw, hh = region["width"] // 2, region["height"] // 2
                region.update({"left": x - hw, "top": y - hh})
                del region["center"]

            monitor = sct.monitors[1]
            region["left"] = max(0, min(region["left"], monitor["width"] - region["width"]))
            region["top"] = max(0, min(region["top"], monitor["height"] - region["height"]))

            filename = f"{SAVE_DIR}/{FILE_PREFIX}_{now_ms()}_region.png"
            sct_img = sct.grab(region)
            sct_img.save(filename, "PNG")
            print(f"Saved region: {filename}")

        # --- Compute both hashes ---
        try:
            sha256_hash = file_sha256(filename)
            murmur_hash = file_murmur3(filename)
            append_block_to_chain(filename, sha256_hash, murmur_hash)
        except Exception as e:
            print(f"Error hashing {filename}: {e}")

# ----------------------------------------------------------------------
# Mouse Listener
# ----------------------------------------------------------------------
def on_click(x, y, button, pressed):
    if pressed:
        print(f"Click at ({x}, {y}) → capturing...")
        threading.Thread(target=capture_screen, args=(x, y), daemon=True).start()

def start_listener():
    print("Listening for clicks… (Ctrl+C to quit)")
    with mouse.Listener(on_click=on_click) as listener:
        try:
            listener.join()
        except KeyboardInterrupt:
            print("\nStopping...")
            stop_listener.set()

# ----------------------------------------------------------------------
# Init: Create files with headers
# ----------------------------------------------------------------------
if not os.path.exists(HASHES_FILE):
    with open(HASHES_FILE, "w", encoding="utf-8") as hf:
        header = (
            "# Screenshot Blockchain Log\n"
            "# Format: timestamp | path | sha256 | murmur3 | prev:<prev_record_hash> | this:<current_record_hash>\n"
            "# -------------------------------------------------------------------------\n"
        )
        hf.write(header)

if not os.path.exists(PREV_HASH_FILE):
    with open(PREV_HASH_FILE, "w", encoding="utf-8") as f:
        f.write("0" * 64)  # Genesis

# ----------------------------------------------------------------------
if __name__ == "__main__":
    start_listener()