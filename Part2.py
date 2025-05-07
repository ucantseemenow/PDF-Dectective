import tkinter as tk
from tkinter import filedialog, messagebox
import PyPDF2
import re
import os

# Keywords to check
MALICIOUS_KEYWORDS = ["/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/AA", "/OpenAction", "/SubmitForm", "/URI"]

# Known-safe generators (e.g., Word, TCPDF, DigiLocker)
TRUSTED_PRODUCERS = ["Microsoft Word", "LibreOffice", "Google", "Adobe", "TCPDF", "DigiLocker"]

def is_suspicious(raw_text):
    suspicious_found = []
    for keyword in MALICIOUS_KEYWORDS:
        if re.search(rf"{re.escape(keyword)}", raw_text):
            suspicious_found.append(keyword)
    return suspicious_found

def check_metadata(reader):
    meta = reader.metadata
    producer = str(meta.get('/Producer', '')).lower()
    author = str(meta.get('/Author', '')).lower()
    for safe in TRUSTED_PRODUCERS:
        if safe.lower() in producer or safe.lower() in author:
            return False, producer
    return True, producer or "Unknown"

def analyze_pdf(filepath):
    result = {
        "filename": os.path.basename(filepath),
        "suspicious": False,
        "reasons": [],
        "safe_hint": "",
        "error": None
    }
    try:
        with open(filepath, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            metadata_flag, producer = check_metadata(reader)
            raw = f.read().decode('latin1', errors='ignore')
            matches = is_suspicious(raw)

            if matches:
                result["suspicious"] = True
                result["reasons"] = matches

            if not metadata_flag:
                result["safe_hint"] = f"Trusted producer: '{producer}'"
            elif not result["suspicious"]:
                result["safe_hint"] = "No dangerous objects detected."

    except Exception as e:
        result["error"] = str(e)
    return result

def choose_file():
    filepath = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if filepath:
        output_text.delete(1.0, tk.END)
        result = analyze_pdf(filepath)
        output_text.insert(tk.END, f"📄 File: {result['filename']}\n\n")
        if result["error"]:
            output_text.insert(tk.END, f"❌ Error: {result['error']}\n")
        elif result["suspicious"]:
            output_text.insert(tk.END, "⚠️ Suspicious content detected!\n")
            output_text.insert(tk.END, "Indicators:\n")
            for reason in result["reasons"]:
                output_text.insert(tk.END, f" - {reason}\n")
        else:
            output_text.insert(tk.END, "✅ No suspicious content found.\n")
            output_text.insert(tk.END, f"🛡️ {result['safe_hint']}\n")

# GUI Setup
window = tk.Tk()
window.title("PDF Malware Scanner - Smart Edition")
window.geometry("520x430")
window.resizable(False, False)

title = tk.Label(window, text="🕵️ PDF Malware Detection Tool", font=("Arial", 16, "bold"))
title.pack(pady=10)

btn = tk.Button(window, text="📂 Choose PDF File", command=choose_file, font=("Arial", 12))
btn.pack(pady=10)

output_text = tk.Text(window, height=18, width=65, font=("Courier", 10))
output_text.pack(padx=10, pady=10)

footer = tk.Label(window, text="Heuristic scanner v2.0 | Not a replacement for antivirus software", font=("Arial", 8), fg="gray")
footer.pack(pady=5)

window.mainloop()
