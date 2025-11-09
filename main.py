import os
import threading
from datetime import datetime
from mss import mss
from pynput import mouse

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
SAVE_DIR = "./screenshots"                     
FILE_PREFIX = "snapshot"           
CAPTURE_REGION = None  # Set to None for full screen, or dict for region
# Example region around click (200x200 centered on click):
# CAPTURE_REGION = {"width": 200, "height": 200, "center": True}

if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

stop_listener = threading.Event()

def now_ms():
    """Current time with millisecond precision."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")[:-3]   # drop last 3 µs

def capture_screen(x=None, y=None):
    """Take a screenshot (full screen or region around click)."""
    with mss() as sct:
        # Full screen (primary monitor)
        if CAPTURE_REGION is None:
            monitor = sct.monitors[1]  # 1 = primary monitor (0 = virtual/all)
            filename = f"{SAVE_DIR}/{FILE_PREFIX}_{now_ms()}.png"
            sct.shot(mon=1, output=filename)  # ← Use int index!
            print(f"Saved full screen: {filename}")
            return

        # Region around click
        region = CAPTURE_REGION.copy()
        if region.get("center") and x is not None and y is not None:
            hw = region["width"] // 2
            hh = region["height"] // 2
            region.update({
                "left": x - hw,
                "top": y - hh,
            })
            del region["center"]

        # Clamp to screen bounds
        monitor = sct.monitors[1]
        region["left"] = max(0, min(region["left"], monitor["width"] - region["width"]))
        region["top"] = max(0, min(region["top"], monitor["height"] - region["height"]))

        filename = f"{SAVE_DIR}/{FILE_PREFIX}_{now_ms()}_region.png"
        sct_img = sct.grab(region)
        sct_img.save(filename, "PNG")
        print(f"Saved region: {filename}")

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
    start_listener()