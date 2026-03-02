# Scout Vulnerability Assessment

A cross-platform security assessment tool for automated vulnerability scanning, user credential testing, and configuration hardening checks on Linux and Windows systems.

## Features

### Service Vulnerability Scanning
- Discovers running services on the target system
- Identifies service versions automatically
- Queries CVE databases to find known vulnerabilities
- Categorizes vulnerabilities as active or possible matches
- Supports both Linux (Debian/RedHat-based) and Windows systems

### User Security Assessment
- Enumerates local user accounts
- Tests user passwords against custom wordlists
- Identifies users with weak credentials
- Detects privileged users (sudo, admin groups)
- Flags high-risk compromised accounts

### Basic Configuration Hardening Checks
- **Apache**: ServerTokens, SSL, directory protections, security headers
- **PostgreSQL**: Authentication settings, SSL configuration, connection restrictions
- **Filezilla**: TLS requirements, password policies, directory listing
- **Nftables/Firewall**: Firewall status and rule validation
- **Windows Registry**: Startup programs, firewall settings

### Automated Reporting
- Generates Excel reports with findings
- Exports PDF reports
- Includes execution time metrics for each scan module

## Installation

### Prerequisites
- Python 3.x
- Administrator/root privileges (required for system enumeration)
- (Optional) NIST NVD API Key (required for CVE querying for the services checks)

### Dependencies
```bash
pip install -r requirements.txt
```

Required packages:
- `progressbar2` - Progress indicators during scans
- `openpyxl` - Excel report generation
- `pam` - PAM authentication (Linux)
- `packaging` - Version comparison
- `aspose-cells-python` - Excel to PDF conversion
- `requests` - CVE database queries
- `python-dotenv` - Loads environment variables from a `.env` file

---

## Environment Configuration

This tool queries the **National Vulnerability Database (NVD)** API.  
You should provide a NIST API key via a `.env` file.

### Create a `.env` file in the project root:

```
NIST_API_KEY=your_actual_nist_api_key_here
```
- The file must be in the same directory where you run `main.py`

### Obtain an API Key

Request a free API key from the NVD website:
https://nvd.nist.gov/developers/request-an-api-key

Without an API key, the tool will fail CVE requests for the service checks.

---

## Usage

### Basic Syntax
```bash
python main.py [OPTIONS]
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-S, --services` | Scan services for CVE vulnerabilities |
| `-U, --crack_users` | Test user passwords with wordlist |
| `-w, --wordlist FILE` | Specify wordlist file for password testing |
| `-C, --configurations` | Check service configurations for misconfigurations |

### Examples

**Scan services for vulnerabilities:**
```bash
python main.py -S
```

**Test user passwords with a wordlist:**
```bash
python main.py -U -w wordlist
```

**Run configuration checks:**
```bash
python main.py -C
```

**Full assessment (all modules):**
```bash
python main.py -S -U -w wordlist -C
```

## Platform Support

### Linux
- **Distributions**: Debian, Ubuntu, Fedora, CentOS, RedHat-based systems
- **Services**: Apache, PostgreSQL, Nftables
- **User enumeration**: PAM-based authentication testing

### Windows
- **Services**: Apache, PostgreSQL, Filezilla, Windows Firewall
- **Registry checks**: Startup programs, firewall status
- **User enumeration**: Windows local accounts and groups

## Output

The tool generates two report files in the current directory:
- `report.xlsx` - Detailed Excel spreadsheet with all findings
- `report.pdf` - PDF export of the Excel report

### Report Sections
1. **Services Report**: Discovered services, versions, CVE matches
2. **User Report**: Vulnerable users, compromised credentials, privileged accounts
3. **Configuration Report**: Misconfiguration findings per service

## Architecture

```
lib/
├── Services/
│   ├── ServiceScanController.py    # Main service scan orchestrator
│   ├── LinuxServicesScanner.py     # Linux service enumeration
│   ├── WinServicesScanner.py       # Windows service enumeration
│   └── CVEUpdater.py               # CVE database queries
├── Users/
│   ├── UserAssessmentController.py # User scan orchestrator
│   ├── LinuxUserAssessment.py      # Linux user enumeration
│   └── WinUserAssessment.py        # Windows user enumeration
├── Configurations/
│   ├── ConfigController.py         # Configuration scan controller
│   ├── LinuxConfigScanner.py       # Linux config checks
│   └── WinConfigScanner.py         # Windows config checks
├── OSProber.py                     # OS detection
└── Reporter.py                     # Report generation
```

## Security Considerations

 **This tool is intended for authorized security assessments only.**

- Requires elevated privileges to access system information
- Password testing can be time-intensive
- Some checks may trigger security monitoring systems
- Only use on systems you own or have explicit permission to test

## License

GNU General Public License v3.0

## Author

Mike K ([@TrailByte](https://github.com/TrailByte))

***

**Note**: This tool was developed as part of a thesis project on system security assessment and hardening.
