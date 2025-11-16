# HashLock-
HashLock is a lightweight file-integrity verification tool that generates secure cryptographic hashes for documents and detects any tampering through baseline comparison. It ensures data authenticity with a simple upload-and-verify workflow using app.py and the advanced audit script review3.py.
# HashLock - Minimal App

This repository contains the two core files from the original Mini Project:
- `app.py` — main application (uploaded as requested)
- `review3.py` — auxiliary review script

## What I included
Only the files you asked to upload were placed here, and I prepared a clean repo layout with a README and .gitignore.

## How to run
1. Create a Python virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate    # on Windows: venv\Scripts\activate
pip install -r requirements.txt  # if you have dependencies
```

2. Run the app:
```bash
python app.py
```

> Note: I have not changed the code. Inspect `app.py` and `review3.py` for any external dependencies (file paths, secret keys, baseline files). See the suggestions in `IMPROVEMENTS.md`.

## Repository layout
```
/ (root)
├─ app.py
├─ review3.py
├─ README.md
├─ IMPROVEMENTS.md
└─ .gitignore
```

## License
Specify your preferred license.

