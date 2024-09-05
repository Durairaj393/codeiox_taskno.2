import psutil
import time
import logging
import smtplib
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import hashlib
import json
import threading

# Configuration
DIRECTORIES_AND_FILES_TO_MONITOR = [
    r"C:\Users\DURAIRAJ\Documents\python11\programs",
    r"C:\Users\DURAIRAJ\Documents\python11\newsampl.py",
    #Directories or Files To Monitor for changes
]

BASELINE_HASHES_FILE = 'baseline_hashes.json'
VIRUSTOTAL_API_KEY = 'virustotal_api_key'
VT_API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
LOG_FILE = 'advanced_hids.log'
EMAIL_FROM = "from_email"
EMAIL_TO = "to_email"
EMAIL_PASSWORD = "email_password"
CPU_USAGE_THRESHOLD = 70.0     #Adjust cpu threshold based on your need 
MEMORY_USAGE_THRESHOLD = 50.0  # Adjust threshold based on your system
DISK_IO_THRESHOLD = 1000000  # Adjust threshold for disk I/O
MONITOR_INTERVAL = 10

# Whitelisted processes and IPs
WHITELIST_PROCESSES = ['System Idle Process', 'python.exe'] # Replace with whitelisted process 
WHITELIST_IPS = ['192.168.1.1', '192.168.1.2']  # Replace with your trusted IPs

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to send alert via email
def send_alert(message):
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_FROM, EMAIL_PASSWORD)
        email_message = f"Subject: HIDS Alert\n\n{message}"
        server.sendmail(EMAIL_FROM, EMAIL_TO, email_message)
        server.quit()
        logging.info(f"Alert sent: {message}")
    except Exception as e:
        logging.error(f"Failed to send alert: {e}")

# Function to calculate SHA256 hash of a file
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None
    return sha256_hash.hexdigest()

# Function to create baseline file hashes
def create_baseline(entries):
    baseline_hashes = {}
    for entry in entries:
        if os.path.isfile(entry):
            baseline_hashes[entry] = calculate_hash(entry)
        elif os.path.isdir(entry):
            for root, _, files in os.walk(entry):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    baseline_hashes[file_path] = calculate_hash(file_path)
    with open(BASELINE_HASHES_FILE, 'w') as f:
        json.dump(baseline_hashes, f)
    logging.info("Baseline hashes created.")

# Function to load baseline hashes
def load_baseline():
    if os.path.exists(BASELINE_HASHES_FILE):
        with open(BASELINE_HASHES_FILE, 'r') as f:
            return json.load(f)
    else:
        logging.error("Baseline hashes file not found. Please create a baseline first.")
        return {}

# Function to check file with VirusTotal
def check_virustotal(file_hash):
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    response = requests.get(VT_API_URL, params=params)
    result = response.json()
    if result['response_code'] == 1:
        positives = result['positives']
        total = result['total']
        if positives > 0:
            return True
    return False

# Function to monitor file integrity
def monitor_files(baseline_hashes):
    for file_path in baseline_hashes.keys():
        if os.path.exists(file_path):
            current_hash = calculate_hash(file_path)
            if current_hash is None:
                continue
            if current_hash != baseline_hashes[file_path]:
                message = f"File integrity violation detected: {file_path}"
                logging.warning(message)
                if check_virustotal(current_hash):
                    send_alert(f"Malicious file detected: {file_path}")
                else:
                    send_alert(message)
        else:
            logging.warning(f"File not found: {file_path}")

# Class to handle file system changes
class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, baseline_hashes):
        self.baseline_hashes = baseline_hashes

    def on_modified(self, event):
        if event.src_path in self.baseline_hashes:
            logging.info(f"Modification detected in {event.src_path}")
            monitor_files(self.baseline_hashes)

    def on_created(self, event):
        if not os.path.isfile(event.src_path):
            return
        logging.info(f"New file detected: {event.src_path}")
        monitor_files(self.baseline_hashes)

    def on_deleted(self, event):
        if event.src_path in self.baseline_hashes:
            logging.info(f"File deleted: {event.src_path}")
            monitor_files(self.baseline_hashes)

# Function to get currently running processes
def get_running_processes():
    processes = {}
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'io_counters']):
        try:
            processes[proc.info['pid']] = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

# Function to monitor processes and detect anomalies
def monitor_processes(baseline_processes):
    time.sleep(MONITOR_INTERVAL)
    current_processes = get_running_processes()
    new_processes = {pid: info for pid, info in current_processes.items() if pid not in baseline_processes}
    if new_processes:
        for pid, info in new_processes.items():
            if info['name'] not in WHITELIST_PROCESSES:
                log_message = f"New process detected: {info['name']} (PID: {pid})"
                logging.info(log_message)
                check_process_behavior(pid, info)

# Function to check process behavior (CPU, memory, disk I/O, and network)
def check_process_behavior(pid, process_info):
    cpu_usage = process_info.get('cpu_percent', 0.0)
    memory_usage = process_info.get('memory_percent', 0.0)
    
    # Get disk I/O counters with default values if not available
    io_counters = process_info.get('io_counters', None)
    if io_counters:
        disk_io = io_counters.write_bytes
    else:
        disk_io = 0  # Set default value if I/O counters are not available

    if cpu_usage > CPU_USAGE_THRESHOLD or memory_usage > MEMORY_USAGE_THRESHOLD or disk_io > DISK_IO_THRESHOLD:
        alert_message = f"[ALERT] High resource usage detected: {process_info['name']} (PID: {pid})"
        logging.warning(alert_message)
        send_alert(alert_message)

    check_network_connections(pid, process_info['name'])


# Function to monitor network connections of a process
def check_network_connections(pid, process_name):
    try:
        process = psutil.Process(pid)
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.raddr and conn.raddr.ip not in WHITELIST_IPS:
                alert_message = f"[ALERT] Suspicious network connection detected: {process_name} (PID: {pid}) to {conn.raddr.ip}"
                logging.warning(alert_message)
                send_alert(alert_message)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

# Function to start the monitoring system
def start_monitoring():
    baseline_processes = get_running_processes()
    logging.info("Starting HIDS monitoring...")

    process_monitor_thread = threading.Thread(target=monitor_processes, args=(baseline_processes,))
    process_monitor_thread.start()

    event_handler = FileChangeHandler(load_baseline())
    observer = Observer()

    for entry in DIRECTORIES_AND_FILES_TO_MONITOR:
        if os.path.isfile(entry):
            directory = os.path.dirname(entry)
            observer.schedule(event_handler, path=directory, recursive=False)
        elif os.path.isdir(entry):
            observer.schedule(event_handler, path=entry, recursive=True)

    observer.start()
    process_monitor_thread.join()

if __name__ == "__main__":
    try:
        create_baseline(DIRECTORIES_AND_FILES_TO_MONITOR)
        while True:
            start_monitoring()
            time.sleep(MONITOR_INTERVAL)
    except KeyboardInterrupt:
        logging.info("HIDS terminated by user.")
