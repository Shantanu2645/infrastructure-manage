#idea: Shantanu Dey Anik
#Code generator: ChatGPT

import re
from collections import Counter
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk
import threading
import time
import csv

def validate_integer(text):
    # Regular expression to check if the input is a valid integer
    pattern = r'^[0-9]+$'
    return re.match(pattern, text) is not None

def parse_access_log(log_file, ip_filter=None):
    ip_pattern = r'(([01]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))'  # Pattern to match IP addresses
    ip_counter = Counter()

    with open(log_file, 'r') as file:
        for line in file:
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip_address = ip_match.group()
                if ip_filter is None or ip_address == ip_filter:
                    ip_counter[ip_address] += 1

    return ip_counter

def filter_ips(ip_counts, count_threshold):
    filtered_ips = [(ip, count) for ip, count in ip_counts.items() if count > count_threshold]
    return sorted(filtered_ips, key=lambda x: x[1], reverse=True)

def sort_table(column):
    current_order = ip_table.heading(column)["text"]  # Get the current sorting order from the column header text
    new_order = "asc" if current_order == column else "desc"
    ip_table.heading(column, text=new_order, command=lambda c=column: sort_table(c))  # Update the column header text
    data = [(ip_table.set(ip, "IP"), ip_table.set(ip, "Count"), ip) for ip in ip_table.get_children("")]
    data.sort(key=lambda x: x[column], reverse=(new_order == "desc"))
    for index, (ip, count, item) in enumerate(data):
        try:
            ip_table.move(item, "", index)
        except tk.TclError:
            ip_table.insert("", index, values=(ip, count))
            ip_table.detach(item)


def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("Log Files", "*.log")])
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

def process_log_file():
    log_file = file_entry.get()
    if not log_file:
        update_error_label("Please select a log file.")
        return

    count_threshold = int(count_entry.get() or 0)  # Set default value of 0 if count_entry is empty
    ip_filter = ip_entry.get()

    # Disable the Process Log button during processing
    process_button.config(state=tk.DISABLED)

    # Create a thread for log processing
    thread = threading.Thread(target=process_log_thread, args=(log_file, count_threshold, ip_filter))
    thread.start()

def process_log_thread(log_file, count_threshold, ip_filter):
    try:
        start_time = time.time()
        ip_counts = parse_access_log(log_file)
        filtered_ips = filter_ips(ip_counts, count_threshold)

        if ip_filter:
            filtered_ips = [(ip, count) for ip, count in filtered_ips if ip == ip_filter]

        elapsed_time = time.time() - start_time
        # Update the GUI with the results
        window.after(0, update_ip_table, filtered_ips, elapsed_time)
    except FileNotFoundError:
        update_error_label("Log file not found.")

    # Enable the Process Log button after processing
    window.after(0, lambda: process_button.config(state=tk.NORMAL))

def update_ip_table(data, elapsed_time):
    ip_table.delete(*ip_table.get_children())
    for ip, count in data:
        ip_table.insert("", tk.END, values=(ip, count))
    update_elapsed_time_label(elapsed_time)
    show_export_button()

def update_elapsed_time_label(elapsed_time):
    elapsed_time_label.config(text=f"Elapsed Time: {elapsed_time:.2f} seconds")

def update_error_label(error_message):
    error_label.config(text=error_message)

def show_export_button():
    export_button.grid(row=2, column=3, padx=5, pady=5)

def export_to_csv():
    file_path = file_entry.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a log file first.")
        return

    file_name = file_path.split("/")[-1].split("\\")[-1]
    csv_file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")], initialfile=f"{file_name}_ip_counts")

    if not csv_file_path:
        return

    data = [(ip_table.set(ip, "IP"), ip_table.set(ip, "Count")) for ip in ip_table.get_children("")]
    try:
        with open(csv_file_path, "w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["IP", "Count"])
            writer.writerows(data)
        messagebox.showinfo("Success", "Data exported to CSV successfully.")
    except IOError:
        messagebox.showerror("Error", "Failed to export data to CSV.")

# Create the main window
window = tk.Tk()
window.title("Access Log Analyzer")

# Create and place the file selection widgets
file_label = tk.Label(window, text="Log File:")
file_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

file_entry = tk.Entry(window, width=50)
file_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

browse_button = tk.Button(window, text="Browse", command=browse_file)
browse_button.grid(row=0, column=2, padx=5, pady=5)

# Create and place the count threshold widgets
count_label = tk.Label(window, text="Count Threshold:")
count_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

count_entry = tk.Entry(window)
count_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
count_entry.insert(0, "0")  # Set default count threshold to 0

# Create and place the IP filter widgets
ip_label = tk.Label(window, text="IP Address:")
ip_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)

ip_entry = tk.Entry(window)
ip_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

process_button = tk.Button(window, text="Process Log", command=process_log_file)
process_button.grid(row=2, column=2, padx=5, pady=5)

# Create and place the IP table
ip_table = ttk.Treeview(window, columns=("IP", "Count"))
ip_table.heading("IP", text="IP", command=lambda: sort_table(0))
ip_table.heading("Count", text="Count", command=lambda: sort_table(1))
ip_table.column("IP", width=200)
ip_table.column("Count", width=100)
ip_table.grid(row=3, column=0, columnspan=4, padx=5, pady=5)

# Create a vertical scroll bar for the IP table
ip_scrollbar = ttk.Scrollbar(window, orient="vertical", command=ip_table.yview)
ip_table.configure(yscrollcommand=ip_scrollbar.set)
ip_scrollbar.grid(row=3, column=4, sticky="ns", padx=5, pady=5)

# Create and place the elapsed time label
elapsed_time_label = tk.Label(window, text="Elapsed Time: 0.00 seconds")
elapsed_time_label.grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)

# Create and place the error label
error_label = tk.Label(window, text="")
error_label.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)

# Create and place the export button (initially hidden)
export_button = tk.Button(window, text="Export to CSV", command=export_to_csv)
export_button.grid(row=2, column=3, padx=5, pady=5)
export_button.grid_remove()

# Start the main window's event loop
window.mainloop()
