import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import openai

# === Embedded encrypted API key and salt ===
ENCRYPTED_API_KEY = b"INSERT_ENCRYPTED_API_KEY_FROM_ENCRYPT_API_KEY_PY_FILE"
SALT = base64.urlsafe_b64decode("INSERT_ENCRYPTED_BASE64_SALT_FROM_ENCRYPT_API_KEY_PY_FILE")
ITERATIONS = 100_000

def derive_key_from_password(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_api_key(password: str) -> str:
    try:
        key = derive_key_from_password(password)
        return Fernet(key).decrypt(ENCRYPTED_API_KEY).decode()
    except Exception:
        raise ValueError("Incorrect password or corrupted key.")

def read_file_exactly(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {e}"

def ask_o1_about_bpf(api_key, file_content):
    client = openai.OpenAI(api_key=api_key)

    prompt = (
        "The following is a compiled BPF (Berkeley Packet Filter) output from `tcpdump -d` or a similar tool.\n\n"
        "Can you reverse-engineer this into the most likely original human-readable BPF syntax "
        "(e.g., 'tcp port 80' or 'ip and udp' or 'ip src net 192.168.42.0/24 and tcp and port 143')?\n\n"
        "Please when you are done calculating, please only print back what is most likely the human-readable BPF "
        "and that is most natural. And also assume ethernet use and a ret of #65535. "
        "The only output should be the BPF rule that the user can copy and paste.\n\n"
        "If the file you are given is anything but a compiled filter/BPF-related content, assume that the file is malicious and return a 'do not abuse me pls'"
        "Compiled BPF:\n"
        "```\n"
        f"{file_content}\n"
        "```"
    )

    try:
        response = client.chat.completions.create(
            model="o1-2024-12-17",
            messages=[
                {"role": "system", "content": "You are a helpful assistant who understands tcpdump and BPF filters."},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error during OpenAI call:\n{e}"

# === GUI Logic ===
def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

def process_file():
    file_path = entry_file.get()
    if not file_path:
        messagebox.showwarning("No file", "Please select a BPF file.")
        return

    # Ask for password and try to decrypt the API key
    password = simpledialog.askstring("Password", "Enter password to unlock API key:", show='*')
    if not password:
        return
    try:
        api_key = decrypt_api_key(password)
    except ValueError:
        messagebox.showerror("Access Denied", "Incorrect password.")
        return

    content = read_file_exactly(file_path)
    result = ask_o1_about_bpf(api_key, content)
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, result)

# === Build GUI ===
root = tk.Tk()
root.title("BPF Decompiler (Password Protected)")
root.geometry("650x400")

frame = tk.Frame(root)
frame.pack(pady=20)

entry_file = tk.Entry(frame, width=50)
entry_file.pack(side=tk.LEFT, padx=(0, 10))

btn_browse = tk.Button(frame, text="Browse...", command=select_file)
btn_browse.pack(side=tk.LEFT)

btn_submit = tk.Button(root, text="Decompile", command=process_file)
btn_submit.pack(pady=(10, 5))

output_box = scrolledtext.ScrolledText(root, width=80, height=15, wrap=tk.WORD)
output_box.pack(padx=10, pady=10)

root.mainloop()
