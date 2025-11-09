import os
import threading
import hashlib
from datetime import datetime
from mss import mss
from pynput import mouse

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
SAVE_DIR = "./screenshots"
HASHES_FILE = "./hashes.txt"                     # <-- file that stores all hashes
FILE_PREFIX = "snapshot"
CAPTURE_REGION = None  # None = full screen, or dict for region around click

if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

stop_listener = threading.Event()


def now_ms():
    """Current time with millisecond precision."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")[:-3]   # drop last 3 µs


def file_hash(filepath: str, chunk_size: int = 8192) -> str:
    """Return SHA-256 hex digest of the file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def append_hash_to_file(filename: str, file_hash: str):
    """Append a line: <timestamp> <relative_path> <sha256>"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    rel_path = os.path.relpath(filename, start=os.path.dirname(HASHES_FILE))
    line = f"{timestamp} | {rel_path} | {file_hash}\n"
    with open(HASHES_FILE, "a", encoding="utf-8") as hf:
        hf.write(line)


def capture_screen(x=None, y=None):
    """Take a screenshot and store its hash."""
    with mss() as sct:
        # --------------------------------------------------------------
        # 1. Determine region / monitor
        # --------------------------------------------------------------
        if CAPTURE_REGION is None:                     # full screen
            monitor = sct.monitors[1]                  # primary monitor
            filename = f"{SAVE_DIR}/{FILE_PREFIX}_{now_ms()}.png"
            sct.shot(mon=1, output=filename)
            print(f"Saved full screen: {filename}")
        else:                                          # region around click
            region = CAPTURE_REGION.copy()
            if region.get("center") and x is not None and y is not None:
                hw = region["width"] // 2
                hh = region["height"] // 2
                region.update({
                    "left": x - hw,
                    "top":  y - hh,
                })
                del region["center"]

            monitor = sct.monitors[1]
            # clamp to screen bounds
            region["left"] = max(0, min(region["left"], monitor["width"] - region["width"]))
            region["top"]  = max(0, min(region["top"],  monitor["height"] - region["height"]))

            filename = f"{SAVE_DIR}/{FILE_PREFIX}_{now_ms()}_region.png"
            sct_img = sct.grab(region)
            sct_img.save(filename, "PNG")
            print(f"Saved region: {filename}")

        # --------------------------------------------------------------
        # 2. Compute hash + write to hashes.txt
        # --------------------------------------------------------------
        try:
            img_hash = file_hash(filename)
            append_hash_to_file(filename, img_hash)
            print(f"Hash ({img_hash[:8]}…) stored in {HASHES_FILE}")
        except Exception as e:
            print(f"Warning: Could not hash {filename}: {e}")


def on_click(x, y, button, pressed):
    if pressed:
        print(f"Click detected: {button} at ({x}, {y})")
        threading.Thread(target=capture_screen, args=(x, y), daemon=True).start()


def start_listener():
    print("Listening for clicks… (Ctrl+C to quit)")
    with mouse.Listener(on_click=on_click) as listener:
        try:
            listener.join()
        except KeyboardInterrupt:
            print("\nStopping...")
            stop_listener.set()


if __name__ == "__main__":
    # Create the hashes file with a header (once)
    if not os.path.exists(HASHES_FILE):
        with open(HASHES_FILE, "w", encoding="utf-8") as hf:
            hf.write("# timestamp                | relative_path                | sha256\n")
            hf.write("#" + "-"*70 + "\n")
    start_listener()