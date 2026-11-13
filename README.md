# Password Strength Checker

A desktop app built with Python and tkinter that evaluates how strong a password is and gives instant feedback.

## Features
- Live strength meter (Very Weak → Very Strong) with a 0-100 score
- Requirements checklist (length, upper/lowercase, numbers, special characters)
- Entropy estimate and approximate time-to-crack
- Detects common passwords, keyboard sequences (`qwerty`, `1234`) and repeated characters
- Improvement suggestions
- Show/hide password toggle
- Secure random password generator
- Nothing is stored or sent over the network

## Project structure
```
password_checker.py   # scoring logic (no UI)
app.py                # tkinter user interface
README.md
```

## How to run
1. Install Python 3.8+ (tkinter is included with the standard Windows/macOS installer).
2. Open the project folder in VS Code.
3. Open the terminal and run:
   ```
   python app.py
   ```
   (On some systems use `python3 app.py`.)

On Linux, if you get "No module named tkinter": `sudo apt install python3-tk`.

## How scoring works
Strength is based on estimated entropy (`length × log2(character pool size)`), reduced by penalties for common passwords, sequences, repeats and low character variety. Short passwords are capped so they can never appear strong.
