from mss import mss

with mss() as sct:
    print("Monitors:", sct.monitors)