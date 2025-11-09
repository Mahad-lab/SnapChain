from pynput import mouse

def on_click(x, y, button, pressed):
    if pressed:
        print(f"Click detected: {button} at ({x}, {y})")
        return False  # Stop after first click for testing

print("Tap or click anywhere... (it should print and exit)")
with mouse.Listener(on_click=on_click) as listener:
    listener.join()