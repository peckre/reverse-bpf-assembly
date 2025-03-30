# 🔍 BPF Decompiler GUI (GPT-o1 Powered)

A Python-based GUI that reverse-engineers **compiled BPF (Berkeley Packet Filter)** output into the most likely original human-readable syntax, using OpenAI's `o1-2024-12-17` model.

---

## ✨ Features

- 🧠 Reasoning-powered BPF decompilation
- 📁 File selector for loading compiled BPF output (e.g. from `tcpdump -d`)
- 🔐 Two versions of the application:
  - **Encrypted API Key**: Secure, password-unlocked decryption of embedded key
  - **User Input API Key**: Prompts for API key at runtime
- 🔄 Live status feedback while the request is processing (User Input Only)
- 🧵 Responsive threading — no GUI freezes (User Input Only)

---

## 📁 Files

| File                  | Description                                                   |
|-----------------------|---------------------------------------------------------------|
| `bpf_gui.py`          | 🔐 Uses encrypted, password-unlocked OpenAI API key           |
| `bpf_gui_userkey.py`  | 🔑 Prompts user to enter their OpenAI API key at runtime      |
| `encrypt_api_key.py`  | 🔐 Helper script to encrypt your API key with a password      |

---

## 🔐 Version 1: Encrypted API Key (bpf_gui.py)

1. Run the helper:
   ```bash
   python encrypt_api_key.py
   ```
2. Enter your OpenAI API key and a password.
3. Copy the generated `ENCRYPTED_API_KEY` and `SALT` into `bpf_gui.py`:
   ```python
   ENCRYPTED_API_KEY = b"..."
   SALT = base64.urlsafe_b64decode("...")
   ```

4. Run the GUI:
   ```bash
   python bpf_gui.py
   ```

You'll be prompted for your password to unlock the key and select a file to decompile. This is optimal if you want to compile a standalone executable.

---

## 🔑 Version 2: Runtime API Key Entry (bpf_gui_userkey.py)

No setup needed. Run:
```bash
python bpf_gui_userkey.py
```

You'll be prompted to:
- Enter your OpenAI API key
- Select a compiled BPF file (e.g. from `tcpdump -d`)

---

## 📄 Example Input

Example `test.txt`:
```
(000) ldh      [12]
(001) jeq      #0x800           jt 2    jf 8
(002) ldb      [14]
(003) and      #0xf
(004) jgt      #0x5             jt 5    jf 8
(005) ldh      [16]
(006) jgt      #0x258           jt 7    jf 8
(007) ret      #65535
(008) ret      #0
```

Example Output:
```
ip and (ip[0] & 0x0f > 5) and (ip[2:2] > 600)
```

---

## 🧠 Requirements

This requires an OpenAI API key. You can get one from the OpenAI website. Multiple models were tested against this requirement; O-1 is the most optimal presently. 

Install dependencies:
```bash
pip install openai cryptography
```

Tkinter is included with most Python distributions. If not:
- On Ubuntu/Debian: `sudo apt install python3-tk`
- On Windows: Already included with python.org installer

---

## 🖥 Usage Overview

1. Launch either script (`bpf_gui.py` or `bpf_gui_userkey.py`)
2. Select a `.txt` file containing compiled BPF output
3. View the GPT-decoded, human-readable BPF rule

---
