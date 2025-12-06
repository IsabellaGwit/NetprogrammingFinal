# DHCP Catcher
## Disclaimer:
This project is for educational purposes only. Do not use it to attack networks without permission. Unauthorized use may violate laws and regulations.

---

## Requirements

This project is designed for Kali Linux or any modern Linux distribution that includes:

- tcpdump
- bash
- sudo privileges
- A VM environment (VirtualBox, VMware, etc.)
- Yersinia

---

## Installation

1. **Clone this repository** (or download ZIP):

git clone https://github.com/IsabellaGwit/NetProgrammingFinal.git
cd dhcp_ids

2. Create and activate a virtual environment:
  
  python -m venv .venv
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
  
Make the script executable:
  .\.venv\Scripts\Activate.ps1
  
  chmod +x dhcp_ids.sh

## Usage

Run the IDS script with root privileges:
sudo ./dhcp_ids.sh

The IDS will:

- Listen on all network interfaces
- Count DHCP Discover packets every second
- Evaluate the total count every 10 seconds
- Trigger an alert if the Discover rate exceeds the threshold
