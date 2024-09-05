# Advanced HIDS (Host-based Intrusion Detection System)

This project is an advanced Host-based Intrusion Detection System (HIDS) that continuously monitors file integrity, process behavior, and resource usage. It also integrates with the VirusTotal API for malware detection and provides real-time alerts via email.

## Features

- **File Integrity Monitoring**: Monitors specified files and directories for unauthorized changes. Automatically checks new or modified files with the VirusTotal API for malware detection.
- **Process Monitoring**: Logs new processes and monitors them for suspicious activities based on CPU, memory usage, disk I/O, and network connections.
- **Real-time Alerts**: Sends email notifications for high-priority events, such as malicious file detection, high resource usage, and suspicious network connections.
- **Logging**: Maintains detailed logs of all monitored events for audit purposes.

## Installation

1. Clone the repository:
   git clone https://github.com/Durairaj393/codeiox_taskno.2.git
   cd yourrepository
   
2. Create and activate a virtual environment (optional but recommended):
  python -m venv venv
  source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
3. Install dependencies:
  pip install -r requirements.txt


Configuration

    Directories and Files to Monitor:
        Modify the DIRECTORIES_AND_FILES_TO_MONITOR list in the script to include the paths of files and directories you want to monitor for changes.

    VirusTotal API Key:
        Set your VirusTotal API key in the VIRUSTOTAL_API_KEY variable.

    Email Configuration:
        Set your email credentials in the EMAIL_FROM, EMAIL_TO, and EMAIL_PASSWORD variables to enable real-time alerting.

    Thresholds:
        Adjust the CPU_USAGE_THRESHOLD, MEMORY_USAGE_THRESHOLD, and DISK_IO_THRESHOLD based on your system and requirements.

    Whitelisting:
        Add processes and IP addresses to the WHITELIST_PROCESSES and WHITELIST_IPS lists to prevent unnecessary alerts.
  4. Start Monitoring:

    Run the script to start the monitoring system:
    python hids.py
  5. Stop Monitoring:
     Ctrl + C
     
