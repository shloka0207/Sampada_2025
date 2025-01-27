import tkinter as tk
from tkinter import ttk, filedialog
import subprocess
import os
import threading
import time

# Constants for button width
BUTTON_WIDTH = 20

# Global variable to store the selected file path
selected_file = None

# Utility function to run shell commands
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        return result.stdout + result.stderr
    except Exception as e:
        return str(e)

# Task execution with threading for better UI responsiveness
def execute_task(task_name, task_function, file_path=None):
    status_label.config(text=f"Executing {task_name}...")
    threading.Thread(target=run_task, args=(task_name, task_function, file_path)).start()

def run_task(task_name, task_function, file_path):
    output = task_function(file_path)
    log_text.insert(tk.END, f"[{task_name}]\n{output}\n")
    log_text.yview(tk.END)
    status_label.config(text="Ready")

# Firmware extraction functions
def extract_firmware(file_path):
    if not file_path:
        return "No file selected."
    output_dir = os.path.join(os.getcwd(), "extracted")
    os.makedirs(output_dir, exist_ok=True)
    command = f"binwalk --run-as=root -e {file_path} -C {output_dir}"
    return run_command(command)

def run_binwalk_analysis(file_path):
    if not file_path:
        return "No file selected."
    command = f"binwalk {file_path}"
    return run_command(command)

def extract_bootloader(file_path):
    if not file_path:
        return "No file selected."
    command = f"dd if={file_path} of=bootloader.bin bs=512 count=1"
    return run_command(command)

def analyze_header(file_path):
    if not file_path:
        return "No file selected."
    command = f"hexdump -C {file_path} | head -n 20"
    return run_command(command)

def parse_firmware_metadata(file_path):
    if not file_path:
        return "No file selected."
    command = f"strings {file_path} | grep -i 'version\|build\|author'"
    return run_command(command)

def run_strings_command(file_path):
    if not file_path:
        return "No file selected."
    command = f"strings {file_path}"
    return run_command(command)

def extract_filesystem(file_path):
    if not file_path:
        return "No file selected."
    command = f"binwalk -Me {file_path}"
    return run_command(command)

def scan_for_embedded_files(file_path):
    if not file_path:
        return "No file selected."
    command = f"binwalk --dd='.*' {file_path}"
    return run_command(command)

# Static analysis functions
def analyze_compression_methods(file_path):
    if not file_path:
        return "No file selected."
    command = f"binwalk -R 'gzip\|xz\|lzma\|bzip2' {file_path}"
    return run_command(command)

def decompress_firmware(file_path):
    if not file_path:
        return "No file selected."
    command = f"gzip -d {file_path} 2>&1 || xz -d {file_path} 2>&1 || bzip2 -d {file_path}"
    return run_command(command)

def identify_file_types(file_path):
    if not file_path:
        return "No file selected."
    command = f"file {file_path}"
    return run_command(command)

def analyze_backdoors(file_path):
    if not file_path:
        return "No file selected."
    command = f"strings {file_path} | grep -i 'password\|backdoor\|key'"
    return run_command(command)

def analyze_encryption_methods(file_path):
    if not file_path:
        return "No file selected."
    command = f"strings {file_path} | grep -i 'AES\|RSA\|encryption'"
    return run_command(command)

# Security checks
def check_for_rootkits(file_path):
    if not file_path:
        return "No file selected."
    command = f"chkrootkit -q {file_path}"
    return run_command(command)

def analyze_network_traffic(file_path):
    if not file_path:
        return "No file selected."
    command = f"tcpdump -nnr {file_path}"
    return run_command(command)

def generate_report(file_path):
    if not file_path:
        return "No file selected."
    report_file = "analysis_report.txt"
    with open(report_file, "w") as report:
        report.write("Firmware Analysis Report\n")
        report.write("=======================\n\n")
        report.write(run_binwalk_analysis(file_path))
        report.write("\n\n")
        report.write(parse_firmware_metadata(file_path))
    return f"Report generated: {report_file}"

# File selection

def select_file():
    global selected_file
    selected_file = filedialog.askopenfilename(title="Select a firmware file", filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")])
    if selected_file:
        selected_file_label.config(text=f"Selected file: {selected_file}")
    return selected_file

# UI Initialization
root = tk.Tk()
root.title("Advanced Firmware Analysis Tool")
root.geometry("1200x800")

# Style configuration
style = ttk.Style()
style.configure('TButton', font=('Helvetica', 10, 'bold'), padding=6, width=BUTTON_WIDTH)
style.configure('TLabel', font=('Helvetica', 12))

# Paned window for layout
paned_window = ttk.Panedwindow(root, orient='horizontal')
paned_window.pack(fill='both', expand=True)

# Left navigation panel
tab_frame = ttk.Frame(paned_window, width=200)
content_frame = ttk.Frame(paned_window)
paned_window.add(tab_frame, weight=1)
paned_window.add(content_frame, weight=4)

# Tab configuration
tab_titles = ["Firmware Extraction", "Static Analysis", "Security Checks", "Report Generation"]
def switch_tab(index):
    for widget in content_frame.winfo_children():
        widget.destroy()
    tab_functions = {
        "Firmware Extraction": [
            ("Extract Firmware", extract_firmware),
            ("Run Binwalk Analysis", run_binwalk_analysis),
            ("Extract Bootloader", extract_bootloader),
            ("Analyze Header", analyze_header),
            ("Parse Metadata", parse_firmware_metadata),
            ("Run Strings", run_strings_command),
            ("Extract Filesystem", extract_filesystem),
        ],
        "Static Analysis": [
            ("Analyze Compression", analyze_compression_methods),
            ("Decompress Firmware", decompress_firmware),
            ("Identify File Types", identify_file_types),
            ("Analyze Backdoors", analyze_backdoors),
            ("Analyze Encryption", analyze_encryption_methods),
        ],
        "Security Checks": [
            ("Check for Rootkits", check_for_rootkits),
            ("Analyze Network Traffic", analyze_network_traffic),
        ],
        "Report Generation": [
            ("Generate Report", generate_report),
        ],
    }
    for name, function in tab_functions[tab_titles[index]]:
        ttk.Button(content_frame, text=name, command=lambda f=function: execute_task(name, f, selected_file)).pack(pady=5, fill='x')

for idx, title in enumerate(tab_titles):
    ttk.Button(tab_frame, text=title, command=lambda i=idx: switch_tab(i)).pack(fill='x')

selected_file_label = ttk.Label(tab_frame, text="No file selected")
selected_file_label.pack(pady=5)

ttk.Button(tab_frame, text="Select File", command=select_file).pack(fill='x')

# Log Panel
log_text = tk.Text(root, height=10, wrap='word')
log_text.pack(fill='both', expand=True, padx=10, pady=5)
log_text.insert('end', "Ready for analysis...\n")

# Status Bar
status_label = ttk.Label(root, text="Ready", anchor='w')
status_label.pack(fill='x', side='bottom')

root.mainloop()