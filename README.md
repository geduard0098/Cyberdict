<div align="center">
# Cyberdict

A terminal-based cybersecurity dictionary with an interactive text user interface (TUI) for fast term lookup and exploration.
</div>

# Description
Cyberdict is a Python-powered cybersecurity dictionary designed to run entirely in the terminal using a responsive text user interface (TUI). It allows users to search and explore cybersecurity terms with live autocomplete suggestions, keyboard navigation, and instant term definitions. Built using Python’s standard curses library, Cyberdict requires no external dependencies and runs efficiently on Unix-like systems. The project focuses on speed, usability, and portability, making it ideal for students, security professionals, and anyone learning cybersecurity concepts directly from the command line.

# Getting Started

## Dependencies

- Python 3.8 or newer

- Unix-like operating system (Linux, macOS, WSL)

- Terminal with curses support

- No external Python libraries are required. Cyberdict relies entirely on the Python standard library.

## Installing

1. Clone the repository:
```bash
git clone https://github.com/your-username/cyberdict.git
cd cyberdict
```
2. No additional installation steps are required.

# Executing program

To start Cyberdict, run the script directly with Python:
```bash
python3 cyberdict.py
```
## Controls and usage

Start typing to search for terms with live autocomplete suggestions.

- Use Up / Down arrow keys to navigate suggestions.

- Press TAB to autocomplete the currently selected suggestion.

- Press Enter to view the selected term’s definition.

- Press l (lowercase L) to view all terms in a scrollable list.

- Press q or Ctrl-C to quit the application.

# Help

If you experience issues:

1. Ensure you are running on a Unix-like system with curses support.

2. Confirm your Python version:
```bash
python3 --version
``` 
3. If the UI does not render correctly:

- Resize your terminal window.

- Avoid running inside terminals that do not fully support curses (some minimal IDE terminals).

# Authors

GitHub: @geduard0098

# Version History

0.2

Added interactive TUI with autocomplete and navigation

Improved performance and usability

0.1

Initial Release

# License

This project is licensed under the MIT License — see the LICENSE.md file for details.

# Acknowledgments:

- Built with assistance from ChatGPT and Gemini

- Inspired by classic terminal-based tools and Unix philosophy

- Python curses documentation and examples

- Cybersecurity learning communities (Hack The Box)

