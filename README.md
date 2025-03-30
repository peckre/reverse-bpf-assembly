# BPF Decompiler GUI (GPT-o1 Powered)

A Python-based GUI that reverse-engineers **compiled BPF (Berkeley Packet Filter)** output into the most likely original human-readable syntax, using OpenAI's `o1-2024-12-17` model. I'm unfamiliar with a tool to derive compiled BPF's into their human-readable syntax, so for those that find themselves in a situation where they have the compiled BPF but not the original, this may be helpful for you :)

*NEW* Added Python script for DeepSeek R1 API integration as an alternative in the files section.

---

## Features

- Reasoning-powered BPF decompilation
- File selector for loading compiled BPF output (e.g. from `tcpdump -d`)
- Two versions of the application:
  - **Encrypted API Key**: Secure, password-unlocked decryption of embedded key
  - **User Input API Key**: Prompts for API key at runtime
- Live status feedback while the request is processing (User Input Only)
- Responsive threading — no GUI freezes (User Input Only)

---

## Files

| File                  | Description                                                   |
|-----------------------|---------------------------------------------------------------|
| `bpf_gui.py`          | Uses encrypted, password-unlocked OpenAI API key           |
| `bpf_gui_userkey.py`  | Prompts user to enter their OpenAI API key at runtime      |
| `encrypt_api_key.py`  | Helper script to encrypt your API key with a password      |

---

## Version 1: Encrypted API Key (bpf_gui.py)

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

## Version 2: Runtime API Key Entry (bpf_gui_userkey.py)

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
(001) jeq      #0x800           jt 2    jf 15
(002) ld       [26]
(003) and      #0xffffff00
(004) jeq      #0xc0a82a00      jt 5    jf 15
(005) ldb      [23]
(006) jeq      #0x6             jt 7    jf 15
(007) ldh      [20]
(008) jset     #0x1fff          jt 15   jf 9
(009) ldxb     4*([14]&0xf)
(010) ldh      [x + 14]
(011) jeq      #0x8f            jt 14   jf 12
(012) ldh      [x + 16]
(013) jeq      #0x8f            jt 14   jf 15
(014) ret      #262144
(015) ret      #0
```

Example Output:
```
ip src net 192.168.42.0/24 and tcp port 143
```

---

## Requirements

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
