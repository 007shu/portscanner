import socket
import concurrent.futures
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import time
import subprocess
import threading

# Global config
DEFAULT_TIMEOUT = 1
DEFAULT_THREADS = 100
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Validate and resolve IP or hostname
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

# Get banner
def get_banner(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return s.recv(1024).decode(errors='ignore').strip()
    except:
        return ""

# Scan single port
def scan_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                banner = get_banner(ip, port, timeout)
                return (port, service, banner)
    except Exception as e:
        with open("error_log.txt", "a") as f:
            f.write(f"Error scanning {ip}:{port} - {e}\n")
    return None

# Start scan button logic
def start_scan():
    host = ip_entry.get().strip()
    ip = resolve_ip(host)
    if not ip:
        messagebox.showerror("Invalid Input", f"Cannot resolve hostname: {host}")
        return

    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
        timeout = float(timeout_entry.get())
        max_threads = int(threads_entry.get())
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter valid numeric values.")
        return

    if start_port < 0 or end_port > 65535 or start_port > end_port:
        messagebox.showerror("Invalid Port Range", "Ports must be in range 0-65535.")
        return

    results_text.config(state='normal')
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, f"Scanning {host} ({ip}) from port {start_port} to {end_port}...\n")
    results_text.insert(tk.END, f"{'Port':<10}{'Service':<20}Banner\n")
    results_text.insert(tk.END, "-"*60 + "\n")

    scan_history_log(host, start_port, end_port)

    progress['value'] = 0
    progress['maximum'] = end_port - start_port + 1
    results_text.update()

    open_ports = []

    def scan_and_display():
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(scan_port, ip, port, timeout): port for port in range(start_port, end_port + 1)}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                progress.step(1)
                if result:
                    open_ports.append(result)
                    port, service, banner = result
                    results_text.insert(tk.END, f"{port:<10}{service:<20}{banner}\n")
                    results_text.see(tk.END)

        if not open_ports:
            results_text.insert(tk.END, "\nNo open ports found.\n")
        results_text.config(state='disabled')

    threading.Thread(target=scan_and_display).start()

# Scan common ports only
def scan_common_ports():
    ip = resolve_ip(ip_entry.get().strip())
    if not ip:
        messagebox.showerror("Invalid Host", "Cannot resolve hostname.")
        return

    try:
        timeout = float(timeout_entry.get())
        max_threads = int(threads_entry.get())
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter numeric values for timeout and threads.")
        return

    results_text.config(state='normal')
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, f"Scanning {ip} on common ports...\n")
    results_text.insert(tk.END, f"{'Port':<10}{'Service':<20}Banner\n")
    results_text.insert(tk.END, "-"*60 + "\n")

    progress['value'] = 0
    progress['maximum'] = len(COMMON_PORTS)

    def scan_common():
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(scan_port, ip, port, timeout) for port in COMMON_PORTS]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                progress.step(1)
                if result:
                    port, service, banner = result
                    results_text.insert(tk.END, f"{port:<10}{service:<20}{banner}\n")
                    results_text.see(tk.END)

        results_text.config(state='disabled')

    threading.Thread(target=scan_common).start()

# Save to CSV
def export_csv():
    content = results_text.get(1.0, tk.END)
    with open("scan_results.csv", "w", encoding="utf-8") as f:
        f.write("Port,Service,Banner\n")
        for line in content.splitlines():
            if line.strip() and not line.startswith("Scanning") and not line.startswith("-"):
                parts = line.split(None, 2)
                if len(parts) == 3:
                    f.write(",".join(parts) + "\n")
    messagebox.showinfo("Saved", "Results saved to scan_results.csv")

# Copy to clipboard
def copy_results():
    root.clipboard_clear()
    root.clipboard_append(results_text.get(1.0, tk.END))
    messagebox.showinfo("Copied", "Results copied to clipboard!")

# Run nmap if available
def run_nmap():
    host = ip_entry.get().strip()
    if not host:
        messagebox.showerror("Input Error", "Enter a valid IP or hostname.")
        return

    try:
        output = subprocess.check_output(["nmap", "-sV", host], stderr=subprocess.STDOUT, text=True)
        results_text.config(state='normal')
        results_text.insert(tk.END, "\n\n--- Nmap Output ---\n")
        results_text.insert(tk.END, output)
        results_text.config(state='disabled')
    except FileNotFoundError:
        messagebox.showerror("Nmap Not Found", "Nmap is not installed or not in PATH.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", e.output)

# Dark mode toggle
def toggle_dark_mode():
    theme = style.theme_use()
    if theme == "default":
        style.theme_use("clam")
        root.configure(bg="#2e2e2e")
        frame.configure(style="Dark.TFrame")
    else:
        style.theme_use("default")
        root.configure(bg="SystemButtonFace")
        frame.configure(style="TFrame")

# Scan history
def scan_history_log(host, start_port, end_port):
    with open("scan_history.txt", "a") as f:
        f.write(f"{time.ctime()}: {host} ports {start_port}-{end_port}\n")

# GUI setup
root = tk.Tk()
root.title("Advanced Python Port Scanner")
root.geometry("750x600")
root.resizable(False, False)

style = ttk.Style(root)
frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)

# Input fields
ttk.Label(frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=tk.W)
ip_entry = ttk.Entry(frame, width=30)
ip_entry.grid(row=0, column=1, sticky=tk.W)

ttk.Label(frame, text="Start Port:").grid(row=1, column=0, sticky=tk.W)
start_port_entry = ttk.Entry(frame, width=10)
start_port_entry.grid(row=1, column=1, sticky=tk.W)

ttk.Label(frame, text="End Port:").grid(row=2, column=0, sticky=tk.W)
end_port_entry = ttk.Entry(frame, width=10)
end_port_entry.grid(row=2, column=1, sticky=tk.W)

ttk.Label(frame, text="Timeout (s):").grid(row=3, column=0, sticky=tk.W)
timeout_entry = ttk.Entry(frame, width=10)
timeout_entry.insert(0, str(DEFAULT_TIMEOUT))
timeout_entry.grid(row=3, column=1, sticky=tk.W)

ttk.Label(frame, text="Max Threads:").grid(row=4, column=0, sticky=tk.W)
threads_entry = ttk.Entry(frame, width=10)
threads_entry.insert(0, str(DEFAULT_THREADS))
threads_entry.grid(row=4, column=1, sticky=tk.W)

# Buttons
ttk.Button(frame, text="Start Scan", command=start_scan).grid(row=5, column=0, pady=5)
ttk.Button(frame, text="Scan Common Ports", command=scan_common_ports).grid(row=5, column=1)
ttk.Button(frame, text="Export to CSV", command=export_csv).grid(row=6, column=0)
ttk.Button(frame, text="Copy to Clipboard", command=copy_results).grid(row=6, column=1)
ttk.Button(frame, text="Run Nmap (if installed)", command=run_nmap).grid(row=7, column=0)
ttk.Button(frame, text="Toggle Dark Mode", command=toggle_dark_mode).grid(row=7, column=1)

# Progress Bar
progress = ttk.Progressbar(frame, orient='horizontal', mode='determinate', length=400)
progress.grid(row=8, column=0, columnspan=2, pady=10)

# Output Area
results_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=85, height=20, state='disabled')
results_text.grid(row=9, column=0, columnspan=2, pady=10)

root.mainloop()
