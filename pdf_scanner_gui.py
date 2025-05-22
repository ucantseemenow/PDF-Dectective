import tkinter as tk
from tkinter import filedialog, messagebox
import PyPDF2
import re
import hashlib
import os
import requests
from datetime import datetime

VIRUSTOTAL_API_KEY = "46138c884ccbf7700bf26f61134b3038c076c583705249138390f4814a639368" 


def load_blacklist(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return set(domain.strip().lower() for domain in f if domain.strip())
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load blacklist: {e}")
        return set()

def extract_domains(pdf_path):
    try:
        reader = PyPDF2.PdfReader(pdf_path)
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return set(re.findall(r'https?://(?:www\.)?([^/\s]+)', text))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to extract from PDF: {e}")
        return set()

def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

def scan_virustotal(file_hash):
    if not VIRUSTOTAL_API_KEY:
        return "VirusTotal API Key not provided."
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return f"VirusTotal - Malicious: {stats['malicious']} / Suspicious: {stats['suspicious']}"
    elif response.status_code == 404:
        return "VirusTotal: File not found in database."
    else:
        return f"VirusTotal Error: {response.status_code}"

def save_log(file_path, results, domains, vt_result):
    log_dir = "scan_reports"
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_file = os.path.join(log_dir, f"scan_{timestamp}.log")
    with open(log_file, "w") as f:
        f.write(f"File: {file_path}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write("Malicious domains found:\n")
        for d in results:
            f.write(f" - {d}\n")
        f.write("\nAll extracted domains:\n")
        for d in domains:
            f.write(f" * {d}\n")
        f.write("\n" + vt_result + "\n")
    return log_file

def scan_pdf():
    file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if not file_path:
        return

    blacklist = load_blacklist("a0c74634-7a01-477f-9633-ca0725ef16e1.txt")
    domains = extract_domains(file_path)
    found = domains.intersection(blacklist)
    
    sha256 = compute_sha256(file_path)
    vt_result = scan_virustotal(sha256)

    log_file = save_log(file_path, found, domains, vt_result)

    if found:
        messagebox.showwarning("Malware Detected", f"Malicious domains found:\n{', '.join(found)}\n\n{vt_result}\nLog saved to {log_file}")
    else:
        messagebox.showinfo("Scan Complete", f"No malicious domains found.\n\n{vt_result}\nLog saved to {log_file}")

root = tk.Tk()
root.title("Advanced PDF Malware Scanner")

canvas = tk.Canvas(root, width=400, height=200)
canvas.pack()

label = tk.Label(root, text="Select a PDF to scan", font=("Arial", 14))
canvas.create_window(200, 50, window=label)

scan_button = tk.Button(root, text="Scan PDF", command=scan_pdf, width=20, height=2, bg="red", fg="white")
canvas.create_window(200, 120, window=scan_button)

root.mainloop()
