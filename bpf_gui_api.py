import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
import openai
import threading
import time

# === File Reader ===
def read_file_exactly(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {e}"

# === GPT Query ===
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

    api_key = simpledialog.askstring("API Key", "Enter your OpenAI API key:", show='*')
    if not api_key:
        return

    content = read_file_exactly(file_path)

    # Start status updater
    status_running[0] = True
    threading.Thread(target=update_status, daemon=True).start()

    def run_request():
        result = ask_o1_about_bpf(api_key, content)

        output_box.after(0, lambda: output_box.delete(1.0, tk.END))
        output_box.after(0, lambda: output_box.insert(tk.END, result))
        status_label.after(0, lambda: status_label.config(text="Done."))
        status_running[0] = False

    threading.Thread(target=run_request, daemon=True).start()

status_running = [False]

def update_status():
    dots = 0
    while status_running[0]:
        msg = "Waiting for response" + "." * (dots % 4)
        status_label.after(0, lambda m=msg: status_label.config(text=m))
        dots += 1
        time.sleep(1.5)

# === Build GUI ===
root = tk.Tk()
root.title("BPF Decompiler (Enter API Key)")
root.geometry("650x420")

frame = tk.Frame(root)
frame.pack(pady=20)

entry_file = tk.Entry(frame, width=50)
entry_file.pack(side=tk.LEFT, padx=(0, 10))

btn_browse = tk.Button(frame, text="Browse...", command=select_file)
btn_browse.pack(side=tk.LEFT)

btn_submit = tk.Button(root, text="Decompile", command=process_file)
btn_submit.pack(pady=(10, 5))

status_label = tk.Label(root, text="", fg="blue")
status_label.pack()

output_box = scrolledtext.ScrolledText(root, width=80, height=15, wrap=tk.WORD)
output_box.pack(padx=10, pady=10)

root.mainloop()
