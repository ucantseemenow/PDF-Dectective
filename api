import tkinter as tk
from tkinter import filedialog, messagebox
import PyPDF2
import yara
import requests
import hashlib
import os
import datetime

# === CONFIGURATION ===
VT_API_KEY = "46138c884ccbf7700bf26f61134b3038c076c583705249138390f4814a639368"
VT_URL = "https://www.virustotal.com/api/v3/files/"

YARA_RULE = '''
rule SuspiciousPDF
{
    strings:
        $js = "/JavaScript"
        $launch = "/Launch"
        $embedded = "/EmbeddedFile"
        $action = "/OpenAction"
    condition:
        any of them
}
'''

# === UTILITY FUNCTIONS ===

def get_hashes(filepath):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def yara_scan(raw_data):
    rules = yara.compile(source=YARA_RULE)
    matches = rules.match(data=raw_data)
    return [str(m.rule) for m in matches]

def virus_total_lookup(sha256):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(VT_URL + sha256, headers=headers)
    if response.status_code == 200:
        json_data = response.json()
        stats = json_data["data"]["attributes"]["last_analysis_stats"]
        return stats
    else:
        return {"error": f"VirusTotal lookup failed. HTTP {response.status_code}"}

def analyze_pdf(filepath):
    result = {
        "filename": os.path.basename(filepath),
        "suspicious": False,
        "yara_matches": [],
        "vt_result": {},
        "hashes": {},
        "safe_hint": "",
        "error": None
    }

    try:
        md5, sha1, sha256 = get_hashes(filepath)
        result["hashes"] = {"MD5": md5, "SHA-1": sha1, "SHA-256": sha256}

        with open(filepath, 'rb') as f:
            raw = f.read()
            result["yara_matches"] = yara_scan(raw)
            if result["yara_matches"]:
                result["suspicious"] = True

        result["vt_result"] = virus_total_lookup(sha256)

    except Exception as e:
        result["error"] = str(e)

    return result

def save_report(scan_result):
    now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"pdf_scan_report_{now}.txt"
    with open(report_name, "w") as f:
        f.write(f"PDF Malware Scan Report - {scan_result['filename']}\n")
        f.write("=" * 60 + "\n")
        f.write("File Hashes:\n")
        for k, v in scan_result["hashes"].items():
            f.write(f" - {k}: {v}\n")
        f.write("\nYARA Matches:\n")
        if scan_result["yara_matches"]:
            for match in scan_result["yara_matches"]:
                f.write(f" - {match}\n")
        else:
            f.write(" None\n")
        f.write("\nVirusTotal Results:\n")
        vt = scan_result["vt_result"]
        if "error" in vt:
            f.write(f" Error: {vt['error']}\n")
        else:
            for k, v in vt.items():
                f.write(f" - {k}: {v}\n")
        f.write("\nFinal Verdict:\n")
        f.write(" ⚠️ Suspicious\n" if scan_result["suspicious"] else " ✅ Clean\n")
    return report_name

# === GUI ===

def choose_file():
    filepath = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if filepath:
        output_text.delete(1.0, tk.END)
        result = analyze_pdf(filepath)
        output_text.insert(tk.END, f"📄 File: {result['filename']}\n\n")
        if result["error"]:
            output_text.insert(tk.END, f"❌ Error: {result['error']}\n")
            return

        for k, v in result["hashes"].items():
            output_text.insert(tk.END, f"{k}: {v}\n")
        output_text.insert(tk.END, "\nYARA Matches:\n")
        if result["yara_matches"]:
            for match in result["yara_matches"]:
                output_text.insert(tk.END, f" - {match}\n")
        else:
            output_text.insert(tk.END, " None\n")

        output_text.insert(tk.END, "\nVirusTotal Analysis:\n")
        vt = result["vt_result"]
        if "error" in vt:
            output_text.insert(tk.END, f" Error: {vt['error']}\n")
        else:
            for k, v in vt.items():
                output_text.insert(tk.END, f" {k}: {v}\n")

        verdict = "⚠️ Suspicious PDF\n" if result["suspicious"] else "✅ Clean PDF\n"
        output_text.insert(tk.END, f"\nVerdict: {verdict}")

        # Offer to save report
        if messagebox.askyesno("Save Report", "Would you like to save a detailed scan report?"):
            report_file = save_report(result)
            messagebox.showinfo("Report Saved", f"Saved to {report_file}")

# GUI Setup
window = tk.Tk()
window.title("Advanced PDF Malware Scanner")
window.geometry("600x550")
window.resizable(False, False)

tk.Label(window, text="🔒 Advanced PDF Malware Scanner", font=("Arial", 16, "bold")).pack(pady=10)
tk.Button(window, text="📂 Select PDF", command=choose_file, font=("Arial", 12)).pack(pady=5)

output_text = tk.Text(window, height=25, width=75, font=("Courier", 9))
output_text.pack(padx=10, pady=10)

tk.Label(window, text="Heuristic + YARA + VirusTotal + Hashing | © 2025", font=("Arial", 8), fg="gray").pack(pady=5)

window.mainloop()
