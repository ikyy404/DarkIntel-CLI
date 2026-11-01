# DarkIntel-CLI

A Python-based Cyber Threat Intelligence (CTI) platform for collecting, analyzing, monitoring, and reporting public cybersecurity intelligence through a terminal interface.

## Features

- CISA Known Exploited Vulnerabilities (KEV) monitoring.
- Threat intelligence analysis.
- Smart risk scoring for vulnerability prioritization.
- Exploitability signal tracking.
- Public ransomware and malware advisory monitoring.
- Public breach catalog metadata monitoring.
- Domain exposure metadata checker.
- Markdown CTI report generation.
- PDF report export.
- SQLite local intelligence database.
- Interactive command-line dashboard.

## Requirements

- Python 3
- pip
- Git
- Internet connection for public intelligence feeds

## Installation

Clone the repository:

    git clone https://github.com/ikyy404/DarkIntel-CLI.git
    cd DarkIntel-CLI

Create a virtual environment:

    python -m venv .venv
    source .venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

## Usage

Initialize the database:

    python init_db.py

Launch the dashboard:

    python dashboard.py

Follow the interactive menu to use the available modules.

## Data Sources

- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA Advisories: https://www.cisa.gov/news-events/cybersecurity-advisories
- Have I Been Pwned: https://haveibeenpwned.com/

## Important Limitations

- CISA KEV inclusion does not prove that a particular system is compromised.
- Smart Risk Scores are prioritization indicators, not probabilities of compromise.
- Confidence scores represent intelligence metadata completeness, not breach probability.
- Public breach catalog matches do not prove ownership of a domain or exposure of a specific account.
- No matching catalog entry does not prove that a domain has never been affected.
- The ransomware tracker monitors public advisories, not live attacks.
- Remediation due dates are not breach dates.

## Security and Ethical Scope

DarkIntel-CLI is designed for defensive cybersecurity research and education.

- Uses public cybersecurity intelligence sources.
- Does not collect, store, or display leaked passwords.
- Does not access private dark web forums.
- Does not download or execute malware.
- Does not execute exploits or test external targets.

Use this project responsibly and only for lawful defensive purposes.

## Data and Privacy

Local databases, generated reports, virtual environments, and secret configuration files are excluded through `.gitignore`.

Never commit passwords, API keys, private intelligence, or personal data.

## License

This project is intended to be distributed under the MIT License. See `LICENSE` for details.
