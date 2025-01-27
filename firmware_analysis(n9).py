import os
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import hashlib
import magic
import math
import re
import matplotlib.pyplot as plt
import subprocess
import binascii

# Existing Functions
def extract_firmware(file_path, output_dir):
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        subprocess.run(["binwalk", "--extract", "--directory", output_dir, file_path], check=True)
        return output_dir
    except Exception as e:
        raise RuntimeError(f"Error during firmware extraction: {e}")

def generate_file_structure(directory, output_file, depth=8):
    try:
        with open(output_file, 'w') as f:
            f.write("# Directory Tree Structure\n")
            for root, dirs, files in os.walk(directory):
                level = root.replace(directory, "").count(os.sep)
                if level > depth:
                    continue
                indent = " " * 4 * level
                f.write(f"{indent}--- {os.path.basename(root)}\n")
                for file in files:
                    file_path = os.path.join(root, file)
                    file_type = magic.from_file(file_path, mime=True)
                    f.write(f"{indent}    --- {file} [{file_type}]\n")
        return output_file
    except Exception as e:
        raise RuntimeError(f"Error generating file structure: {e}")

def analyze_entropy(file_path, output_dir):
    entropy_data = []
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            while chunk:
                histogram = [0] * 256
                for byte in chunk:
                    histogram[byte] += 1
                entropy = 0
                for count in histogram:
                    if count > 0:
                        p = count / len(chunk)
                        entropy -= p * math.log2(p)
                entropy_data.append(entropy)
                chunk = f.read(1024)

        plot_path = os.path.join(output_dir, "entropy_plot.png")
        plt.figure(figsize=(10, 6))
        plt.plot(entropy_data)
        plt.title("Entropy Analysis")
        plt.xlabel("Chunk Index")
        plt.ylabel("Entropy")
        plt.savefig(plot_path)
        plt.close()
        return plot_path, entropy_data
    except Exception as e:
        raise RuntimeError(f"Error during entropy analysis: {e}")

def analyze_firmware_details(file_path, output_dir, entropy_data):
    try:
        report_path = os.path.join(output_dir, "firmware_details.txt")
        with open(report_path, 'w') as report_file:
            file_size = os.path.getsize(file_path)
            md5_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
            file_type = magic.from_file(file_path)
            entropy_avg = sum(entropy_data) / len(entropy_data) if entropy_data else 0

            report_file.write(f"File Size: {file_size:,} bytes\n")
            report_file.write(f"MD5 Hash: {md5_hash}\n")
            report_file.write(f"File Format: {file_type}\n")
            report_file.write(f"Average Entropy: {entropy_avg:.2f}\n")

            urls, ips = set(), set()
            url_regex = r'(https?://[^\s]+)'
            ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

            with open(file_path, 'rb') as f:
                content = f.read().decode(errors='ignore')
                urls.update(re.findall(url_regex, content))
                ips.update(re.findall(ip_regex, content))

            report_file.write(f"Detected URLs: {', '.join(urls) if urls else 'None'}\n")
            report_file.write(f"Detected IP Addresses: {', '.join(ips) if ips else 'None'}\n")

            report_file.write("Metadata:\n")
            report_file.write("- Version: N/A\n")
            report_file.write("- Build Date: N/A\n")
            report_file.write("- Developer: N/A\n")

        return report_path
    except Exception as e:
        raise RuntimeError(f"Error analyzing firmware details: {e}")

def analyze_cryptography(extracted_dir, output_dir):
    try:
        report_path = os.path.join(output_dir, "cryptographic_analysis.txt")
        with open(report_path, 'w') as report_file:
            report_file.write("### Cryptographic Analysis ###\n\n")
            crypto_patterns = {
                "AES": b"AES",
                "RSA": b"RSA",
                "SHA": b"SHA",
                "Private Key": b"PRIVATE KEY",
                "Certificate": b"BEGIN CERTIFICATE"
            }

            for root, _, files in os.walk(extracted_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read()
                            for algo, pattern in crypto_patterns.items():
                                if pattern in content:
                                    report_file.write(f"Detected {algo} in: {file_path}\n")
                    except Exception:
                        continue

        return report_path
    except Exception as e:
        raise RuntimeError(f"Error analyzing cryptography: {e}")

def analyze_passwords(extracted_dir, output_dir):
    try:
        report_path = os.path.join(output_dir, "password_analysis.txt")
        with open(report_path, 'w') as report_file:
            report_file.write("### Password Analysis ###\n\n")

            password_patterns = [
                r'password\s*=\s*["\']?(\w+)["\']?',
                r'pwd\s*=\s*["\']?(\w+)["\']?',
                r'pass\s*=\s*["\']?(\w+)["\']?'
            ]
            passwords = set()

            for root, _, files in os.walk(extracted_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                            for pattern in password_patterns:
                                matches = re.findall(pattern, content)
                                passwords.update(matches)
                    except Exception:
                        continue

            if passwords:
                report_file.write("Detected Passwords:\n")
                report_file.writelines(f"- {password}\n" for password in passwords)
            else:
                report_file.write("No passwords found.\n")

        return report_path
    except Exception as e:
        raise RuntimeError(f"Error analyzing passwords: {e}")

def keyword_based_search(extracted_dir, output_dir):
    try:
        report_path = os.path.join(output_dir, "keyword_analysis.txt")
        with open(report_path, 'w') as report_file:
            report_file.write("### Keyword-based Search ###\n\n")

            keywords = [r'password', r'admin', r'key', r'config', r'user', r'token']
            matches = {}

            for root, _, files in os.walk(extracted_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                            for keyword in keywords:
                                if re.search(keyword, content, re.IGNORECASE):
                                    if file_path not in matches:
                                        matches[file_path] = []
                                    matches[file_path].append(keyword)
                    except Exception:
                        continue

            if matches:
                report_file.write("Detected Keywords:\n")
                for file_path, found_keywords in matches.items():
                    report_file.write(f"- {file_path}: {', '.join(found_keywords)}\n")
            else:
                report_file.write("No keywords found.\n")

        return report_path
    except Exception as e:
        raise RuntimeError(f"Error during keyword-based search: {e}")

def analyze_file_signatures(extracted_dir, output_dir):
    """
    Analyzes files in the extracted firmware directory for file signatures and identifies unknown file types.

    Args:
        extracted_dir (str): Path to the directory containing extracted firmware files.
        output_dir (str): Directory where the file signature analysis report will be saved.

    Returns:
        str: Path to the saved file signature analysis report.
    """
    try:
        # Common file signatures (magic bytes) for known file types
        known_signatures = {
            b"\x89PNG\r\n\x1a\n": "PNG Image",
            b"\xFF\xD8\xFF": "JPEG Image",
            b"\x25\x50\x44\x46": "PDF Document",
            b"\x50\x4B\x03\x04": "ZIP Archive",
            b"\x7F\x45\x4C\x46": "ELF Executable",
            b"\x46\x57\x53": "Flash File",
            b"\x4D\x5A": "Windows Executable (PE)",
            b"\x52\x61\x72\x21": "RAR Archive"
        }

        report_path = os.path.join(output_dir, "file_signature_analysis.txt")
        with open(report_path, 'w') as report_file:
            report_file.write("### File Signature Analysis ###\n\n")

            for root, _, files in os.walk(extracted_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'rb') as f:
                            file_header = f.read(8)  # Read the first 8 bytes of the file
                            signature = binascii.hexlify(file_header).upper()

                            identified = False
                            for known_sig, file_type in known_signatures.items():
                                if file_header.startswith(known_sig):
                                    report_file.write(f"{file_path}: {file_type}\n")
                                    identified = True
                                    break

                            # If no signature matched, mark it as unknown
                            if not identified:
                                report_file.write(f"{file_path}: Unknown file type (Signature: {signature.decode()})\n")

                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")
                        continue

        return report_path
    except Exception as e:
        print(f"Error analyzing file signatures: {e}")
        raise


# GUI Application
def select_firmware():
    file_path = filedialog.askopenfilename(title="Select Firmware File", filetypes=[("All Files", "*.*")])
    if file_path:
        root.destroy()
        main_application(file_path)

def main_application(file_path):
    def run_analysis(option):
        try:
            output_dir = os.path.join(os.getcwd(), "output")
            os.makedirs(output_dir, exist_ok=True)

            if option == "Extract Firmware":
                extract_firmware(file_path, output_dir)
                messagebox.showinfo("Success", "Firmware extracted successfully!")

            elif option == "File Structure":
                output_file = os.path.join(output_dir, "file_structure.txt")
                generate_file_structure(output_dir, output_file)
                messagebox.showinfo("Success", "File structure generated successfully!")

            elif option == "Entropy Analysis":
                entropy_plot, entropy_data = analyze_entropy(file_path, output_dir)
                messagebox.showinfo("Success", f"Entropy analysis completed! Plot saved at {entropy_plot}")

            elif option == "Firmware Details":
                _, entropy_data = analyze_entropy(file_path, output_dir)
                report = analyze_firmware_details(file_path, output_dir, entropy_data)
                messagebox.showinfo("Success", f"Firmware details report generated at {report}")

            elif option == "Cryptographic Analysis":
                extract_firmware(file_path, output_dir)
                report = analyze_cryptography(output_dir, output_dir)
                messagebox.showinfo("Success", f"Cryptographic analysis report generated at {report}")

            elif option == "Password Analysis":
                extract_firmware(file_path, output_dir)
                report = analyze_passwords(output_dir, output_dir)
                messagebox.showinfo("Success", f"Password analysis report generated at {report}")

            elif option == "Keyword Search":
                extract_firmware(file_path, output_dir)
                report = keyword_based_search(output_dir, output_dir)
                messagebox.showinfo("Success", f"Keyword search report generated at {report}")

            elif option == "File Signatures":
                extract_firmware(file_path, output_dir)
                report = analyze_file_signatures(output_dir, output_dir)
                messagebox.showinfo("Success", f"File signature analysis report generated at {report}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    app = tk.Tk()
    app.title("Firmware Analysis Tool")

    options = [
        "Extract Firmware",
        "File Structure",
        "Entropy Analysis",
        "Firmware Details",
        "Cryptographic Analysis",
        "Password Analysis",
        "Keyword Search",
        "File Signatures"
    ]

    for option in options:
        button = tk.Button(app, text=option, command=lambda opt=option: run_analysis(opt))
        button.pack(pady=5)

    app.mainloop()

# Main Application Entry
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Select Firmware File")
    select_button = tk.Button(root, text="Select Firmware", command=select_firmware)
    select_button.pack(pady=20)
    root.mainloop()
