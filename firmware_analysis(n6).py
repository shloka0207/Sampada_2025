import os
import hashlib
import magic
import math
import re
import matplotlib.pyplot as plt
from tkinter import Tk, filedialog
import subprocess
import binascii

def extract_firmware(file_path, output_dir):
    """
    Extracts the contents of a firmware binary file using binwalk.

    Args:
        file_path (str): Path to the firmware file.
        output_dir (str): Directory where extracted files will be stored.

    Returns:
        str: Path to the directory where files were extracted.
    """
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Run binwalk to extract files
        subprocess.run(["binwalk", "--extract", "--directory", output_dir, file_path], check=True)
        return output_dir
    except Exception as e:
        print(f"Error during firmware extraction: {e}")
        raise


def generate_file_structure(directory, output_file, depth=8):
    """
    Generates a tree structure of the extracted firmware directory up to a specified depth.

    Args:
        directory (str): Path to the extracted firmware directory.
        output_file (str): Path to save the tree structure markdown file.
        depth (int): Maximum depth of the directory tree.

    Returns:
        str: Path to the markdown file containing the tree structure.
    """
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
        print(f"Error generating file structure: {e}")
        raise


def analyze_entropy(file_path, output_dir):
    """
    Analyzes the entropy of a firmware binary file and generates a plot.

    Args:
        file_path (str): Path to the firmware file.
        output_dir (str): Directory where the entropy plot will be saved.

    Returns:
        tuple: Path to the saved entropy plot and a list of entropy values.
    """
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

        # Plot entropy
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
        print(f"Error during entropy analysis: {e}")
        raise


def analyze_firmware_details(file_path, output_dir, entropy_data):
    """
    Analyzes firmware details including file size, hash, detected URLs, and metadata.

    Args:
        file_path (str): Path to the firmware file.
        output_dir (str): Directory where the analysis report will be saved.
        entropy_data (list): List of calculated entropy values.

    Returns:
        str: Path to the detailed firmware analysis report.
    """
    try:
        report_path = os.path.join(output_dir, "firmware_details.txt")
        with open(report_path, 'w') as report_file:
            # File size and MD5 hash
            file_size = os.path.getsize(file_path)
            md5_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
            file_type = magic.from_file(file_path)
            entropy_avg = sum(entropy_data) / len(entropy_data) if entropy_data else 0

            report_file.write(f"File Size: {file_size:,} bytes\n")
            report_file.write(f"MD5 Hash: {md5_hash}\n")
            report_file.write(f"File Format: {file_type}\n")
            report_file.write(f"Average Entropy: {entropy_avg:.2f}\n")

            # Search for URLs and IP addresses
            urls, ips = set(), set()
            url_regex = r'(https?://[^\s]+)'
            ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

            with open(file_path, 'rb') as f:
                content = f.read().decode(errors='ignore')
                urls.update(re.findall(url_regex, content))
                ips.update(re.findall(ip_regex, content))

            report_file.write(f"Detected URLs: {', '.join(urls) if urls else 'None'}\n")
            report_file.write(f"Detected IP Addresses: {', '.join(ips) if ips else 'None'}\n")

            # Metadata placeholder
            report_file.write("Metadata:\n")
            report_file.write("- Version: N/A\n")
            report_file.write("- Build Date: N/A\n")
            report_file.write("- Developer: N/A\n")

        return report_path
    except Exception as e:
        print(f"Error analyzing firmware details: {e}")
        raise


def analyze_cryptography(extracted_dir, output_dir):
    """
    Searches for cryptographic patterns (algorithms, keys, certificates) in the firmware.

    Args:
        extracted_dir (str): Path to the directory containing extracted firmware files.
        output_dir (str): Directory where the cryptographic report will be saved.

    Returns:
        str: Path to the saved cryptographic analysis report.
    """
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
        print(f"Error analyzing cryptography: {e}")
        raise


def analyze_passwords(extracted_dir, output_dir):
    """
    Searches for plaintext passwords, hashed credentials, or weakly encoded secrets.

    Args:
        extracted_dir (str): Path to the directory containing extracted firmware files.
        output_dir (str): Directory where the password analysis report will be saved.

    Returns:
        str: Path to the saved password analysis report.
    """
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
        print(f"Error analyzing passwords: {e}")
        raise


def keyword_based_search(extracted_dir, output_dir):
    """
    Searches for sensitive keywords (e.g., password, admin, key) across all extracted files.

    Args:
        extracted_dir (str): Path to the directory containing extracted firmware files.
        output_dir (str): Directory where the keyword search report will be saved.

    Returns:
        str: Path to the saved keyword search report.
    """
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
        print(f"Error during keyword-based search: {e}")
        raise


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


def main():
    try:
        Tk().withdraw()  # Hide the root Tkinter window
        firmware_path = filedialog.askopenfilename(title="Select Firmware File", filetypes=[("Binary Files", "*.bin")])
        if not firmware_path:
            print("No file selected.")
            return

        output_dir = os.path.join(os.path.dirname(firmware_path), "analysis_output")
        extracted_dir = os.path.join(output_dir, "extracted")

        # Extract firmware
        extract_firmware(firmware_path, extracted_dir)

        # Generate file structure
        generate_file_structure(extracted_dir, os.path.join(output_dir, "file_structure.md"))

        # Analyze entropy
        entropy_plot_path, entropy_data = analyze_entropy(firmware_path, output_dir)

        # Analyze firmware details
        firmware_details_path = analyze_firmware_details(firmware_path, output_dir, entropy_data)

        # Analyze cryptographic patterns
        cryptographic_analysis_path = analyze_cryptography(extracted_dir, output_dir)

        # Analyze passwords
        password_analysis_path = analyze_passwords(extracted_dir, output_dir)

        # Keyword-based search
        keyword_analysis_path = keyword_based_search(extracted_dir, output_dir)

        # Analyze file signatures
        file_signature_analysis_path = analyze_file_signatures(extracted_dir, output_dir)

        print("Analysis Complete.")
        print(f"Entropy Plot: {entropy_plot_path}")
        print(f"Firmware Details: {firmware_details_path}")
        print(f"Cryptographic Analysis: {cryptographic_analysis_path}")
        print(f"Password Analysis: {password_analysis_path}")
        print(f"Keyword Analysis: {keyword_analysis_path}")
        print(f"File Signature Analysis: {file_signature_analysis_path}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
