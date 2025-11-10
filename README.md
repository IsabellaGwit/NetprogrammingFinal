# DHCP Catcher
## Disclaimer:
This project is for educational purposes only. Do not use it to attack networks without permission. Unauthorized use may violate laws and regulations.

A starter Python project for detecting DHCP activity on your network.  
This project is intended for educational and testing purposes in a controlled environment only.

---

## Requirements

- Python 3.13 or newer  
- Windows (with admin privileges to sniff network packets)  
- [Npcap](https://nmap.org/npcap/) installed  
- `scapy` and `requests` Python packages  

---

## Installation

1. **Clone this repository** (or download ZIP):

  `bash
  git clone https://github.com/<your-username>/<your-repo>.git
  cd dhcp_catcher

2. Create and activate a virtual environment:
  
  python -m venv .venv
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
  .\.venv\Scripts\Activate.ps1

3. Install required packages:

  python -m pip install --upgrade pip
  python -m pip install -r requirements.txt

## Usage

1. List network interfaces:
   
  python - <<'PY'
  from scapy.all import get_if_list
  print(get_if_list())
  PY
  
2. Run the DHCP catcher:
  python dhcp_catcher.py -i "<INTERFACE_NAME>" --verbose
