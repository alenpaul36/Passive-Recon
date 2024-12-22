# Passive Reconnaissance Tool

A powerful passive reconnaissance tool designed for Kali Linux, focusing on gathering intelligence without direct target interaction.

## What is Passive Reconnaissance?

Passive reconnaissance is the practice of gathering information about a target without directly interacting with it. This means:
- No packets are sent to the target systems
- No active scanning or probing is performed
- All information is gathered from public sources and third-party databases
- The target cannot detect or log our reconnaissance activities

## Features and Their Passive Nature

Each feature is designed to be completely passive, gathering information without alerting the target:

- **WHOIS Information**
  - *Passive Method*: Queries public WHOIS databases
  - *No Target Interaction*: Information retrieved from registrar databases only
  - *Data Source*: Public domain registration records

- **DNS Records**
  - *Passive Method*: Queries public DNS servers
  - *No Target Interaction*: No direct queries to target's DNS servers
  - *Data Source*: Public DNS infrastructure

- **SSL Certificate Analysis**
  - *Passive Method*: Retrieves certificates from public certificate transparency logs
  - *No Target Interaction*: No direct SSL handshakes with target
  - *Data Source*: Public certificate databases and logs

- **Security Headers Analysis**
  - *Passive Method*: Analyzes cached responses from public sources
  - *No Target Interaction*: Uses third-party security header databases
  - *Data Source*: Public security scanners and cached results

- **Web Technology Detection**
  - *Passive Method*: Uses BuiltWith API and public technology fingerprints
  - *No Target Interaction*: Relies on pre-collected data
  - *Data Source*: Public technology fingerprint databases

- **Credential Leak Detection**
  - *Passive Method*: Queries HaveIBeenPwned API
  - *No Target Interaction*: Checks against existing breach databases
  - *Data Source*: Public breach repositories and paste sites

- **Secret and Credential Detection**
  - *Passive Method*: Scans public GitHub repositories
  - *No Target Interaction*: Uses GitHub API to search for exposed secrets
  - *Data Source*: Public repositories and gists
  - *Detects*:
    - AWS Keys and Secrets
    - Private Keys (RSA, SSH)
    - GitHub Tokens
    - Google API Keys
    - Firebase URLs
    - Hardcoded Passwords
    - Authorization Headers
    - Other sensitive information

- **Technology Stack Analysis**
  - *Passive Method*: Uses public fingerprint databases
  - *No Target Interaction*: Analyzes publicly available signatures
  - *Data Source*: Public technology catalogs

- **Email Intelligence**
  - *Passive Method*: Queries email reputation databases
  - *No Target Interaction*: Uses pre-collected reputation data
  - *Data Source*: Public email reputation services

## Output and Reporting

### Console Output
- Clean and professional output formatting
- Color-coded status messages for better visibility
- Real-time task completion status
- Parallel execution with proper status tracking

### Comprehensive Report
The tool generates a detailed HTML report with:

- **Domain Analysis**
  - WHOIS information with risk assessment
  - Domain age and expiration analysis
  - Registration details

- **Security Analysis**
  - Security headers evaluation
  - SSL certificate status
  - Technology stack detection
  - DNS record analysis
  - Data breach findings
  - Exposed secrets and credentials
  - Google dorks results
  - Threat intelligence data

- **Risk Assessment**
  - High, Medium, and Low risk categorization
  - Color-coded risk indicators
  - Detailed impact analysis
  - Actionable recommendations

The report is designed to be both comprehensive and actionable, helping security teams identify and address potential vulnerabilities effectively.

## Prerequisites

- Kali Linux (Tested on latest version)
- Python 3.9+
- pip3

## Installation

### 1. System Dependencies

First, install required system packages:

```bash
# Update package list
sudo apt update

# Install system dependencies
sudo apt install -y python3-dev python3-pip python3-venv
sudo apt install -y libssl-dev libffi-dev
sudo apt install -y yara libyara-dev
sudo apt install -y git
```

### 2. Python Environment Setup

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip and setuptools
pip3 install --upgrade pip setuptools wheel

# Install Python dependencies
pip3 install -r requirements.txt
```

### 3. Manual Package Installation (if needed)

If you encounter any package installation issues, install them manually:

```bash
# Core packages
pip3 install requests beautifulsoup4 dnspython whois

# OSINT packages
pip3 install shodan censys builtwith PyGithub

# Security packages
pip3 install yara-python GitPython

# UI packages
pip3 install colorama rich tqdm Jinja2

# Environment and utilities
pip3 install python-dotenv requests-futures
```

### Common Installation Issues

1. **ModuleNotFoundError: No module named 'whois'**
   ```bash
   pip3 uninstall python-whois whois
   pip3 install whois
   ```

2. **SSL/Crypto Errors**
   ```bash
   sudo apt install -y python3-dev libssl-dev libffi-dev
   pip3 install --upgrade cryptography pyOpenSSL
   ```

3. **YARA Installation Issues**
   ```bash
   sudo apt remove -y yara libyara-dev
   sudo apt install -y yara libyara-dev
   pip3 install --no-cache-dir yara-python
   ```

### Verifying Installation

Run this command to verify all dependencies are installed correctly:

```bash
python3 -c "import dns.resolver, requests, bs4, whois, github, yara, git, rich, colorama, builtwith, jinja2, shodan, censys; print('All dependencies successfully imported!')"
```

## Environment Setup

### Setting Up API Keys

#### Method 1: Environment Variables (Recommended)

Add these to your `~/.bashrc` or `~/.zshrc`:

```bash
# GitHub Token
export GITHUB_TOKEN="your_github_token"
# Have I Been Pwned
export HIBP_API_KEY="your_hibp_api_key"
# Shodan
export SHODAN_API_KEY="your_shodan_api_key"
# Censys
export CENSYS_API_ID="your_censys_api_id"
export CENSYS_API_SECRET="your_censys_api_secret"
```

Then reload your shell configuration:
```bash
source ~/.bashrc  # or source ~/.zshrc
```

#### Method 2: Using a .env File

1. Create a `.env` file in the project root:
```bash
cat > .env << EOL
GITHUB_TOKEN=your_github_token
HIBP_API_KEY=your_hibp_api_key
SHODAN_API_KEY=your_shodan_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
EOL
```

2. Set proper permissions:
```bash
chmod 600 .env
```

### Verifying API Key Setup

```bash
python3 -c "import os; keys=['GITHUB_TOKEN', 'HIBP_API_KEY', 'SHODAN_API_KEY', 'CENSYS_API_ID', 'CENSYS_API_SECRET']; [print(f'{k}: {"✓ Set" if os.getenv(k) else "✗ Not Set"}') for k in keys]"
```

### API Key Security Notes

1. Never commit your `.env` file or API keys to version control
2. Set appropriate expiration dates for your API tokens
3. Use tokens with minimal required permissions
4. Regularly rotate your API keys
5. Monitor API key usage for any unauthorized access
6. Ensure proper file permissions for sensitive files:
   ```bash
   chmod 600 .env
   chmod 700 ~/.bashrc
   ```

## API Keys Setup

### GitHub Token Requirements

To use the GitHub secret scanning feature, you need to create a Personal Access Token (PAT) with the following minimum permissions:

1. Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Required permissions:
   - `repo`
     - `repo:status` - Access commit status
     - `repo_deployment` - Access deployment status
     - `public_repo` - Access public repositories
   - `read:org` - Read organization data
   - `read:user` - Read user data
   - `read:packages` - Read packages

Note: The tool only requires read access as it performs passive reconnaissance. No write permissions are needed.

To create your token:
1. Visit: https://github.com/settings/tokens
2. Set an expiration date (recommended: 30 days)
3. Select the permissions listed above
4. Generate token and save it securely
5. Export the token in your environment:
```bash
export GITHUB_TOKEN='your_github_token'
```

### Other API Keys

- Have I Been Pwned API key
```bash
export HIBP_API_KEY='your_hibp_api_key'
```

- Shodan API key
```bash
export SHODAN_API_KEY='your_shodan_api_key'
```

- Censys API credentials
```bash
export CENSYS_API_ID='your_censys_api_id'
export CENSYS_API_SECRET='your_censys_api_secret'
```

## Usage

Basic usage:
```bash
./passive.py example.com
```

With output directory:
```bash
./passive.py example.com -o /path/to/output
```

With specific modules:
```bash
./passive.py example.com --modules dns,ssl,github
```

## Information Gathered (All Passive)

The tool collects the following information without any direct target interaction:

1. **Domain Information** (via public records)
   - WHOIS registration data
   - Historical domain data
   - Registrar information

2. **Technical Data** (via public sources)
   - Public DNS records
   - SSL/TLS certificates from CT logs
   - Historical security headers

3. **Security Assessment** (via third-party databases)
   - Exposed secrets in public repositories
   - API keys and credentials in GitHub
   - Cloud service configurations
   - Hardcoded sensitive information
   - Known credential leaks
   - Public breach data
   - Email reputation data

4. **Infrastructure Analysis** (via public catalogs)
   - Technology stack identification
   - Framework detection
   - Historical infrastructure data

## Data Sources

All information is gathered from these passive sources:
- Public WHOIS databases
- Public DNS resolvers
- Certificate Transparency logs
- HaveIBeenPwned database
- Public email reputation services
- BuiltWith technology database
- Public security scan databases
- Historical data repositories
- Public GitHub repositories

## API Usage and Rate Limits

All APIs are used in a passive manner:
- HIBP API: 1 request per 1.5 seconds
- Shodan: Historical data only
- Censys: Public scan data only
- Email Reputation API: Public reputation data only
- GitHub API: Used for secret scanning

## Security and Privacy Notes

- Completely passive reconnaissance
- No direct target interaction
- No active scanning or probing
- Target cannot detect the reconnaissance
- All data from public sources only

## Error Handling

The tool implements passive-only error handling:
- Graceful degradation when APIs are unavailable
- No fallback to active reconnaissance
- Clear error messages for missing data
- Rate limit compliance

## Contributing

When contributing, ensure all new features maintain the passive-only nature:
1. No direct target interaction
2. Use only public data sources
3. Implement proper rate limiting
4. Document the passive nature of new features

## Legal and Ethical Considerations

- This tool performs only passive reconnaissance
- All information gathered is from public sources
- No active scanning or probing is performed
- Users must comply with applicable laws
- Tool designed for ethical use only

## Disclaimer

This tool is designed for passive reconnaissance only. It does not perform any active scanning or direct interaction with target systems. Users are responsible for ensuring all reconnaissance activities comply with applicable laws and regulations.

## Troubleshooting

### Common Issues

1. Permission Denied
```bash
chmod +x passive.py
```

2. Python Version
```bash
python3 --version  # Should be 3.9+
```

3. Missing Dependencies
```bash
pip3 install -r requirements.txt
```

4. API Key Issues
```bash
# Check if keys are properly set
env | grep -E 'GITHUB_TOKEN|HIBP_API_KEY|SHODAN_API_KEY|CENSYS_API_ID|CENSYS_API_SECRET'
```
