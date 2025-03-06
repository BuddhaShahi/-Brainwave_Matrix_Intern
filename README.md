**Phishing URL Scanner **

A Python-based phishing link scanner that:

- Checks if a URL is blacklisted in OpenPhish
- Retrieves WHOIS domain details (creation & expiration date)
- Processes multiple URLs from a file and saves results in a CSV

**Features**

- Validates URL format\
- Checks against OpenPhish blacklist\
- Extracts domain information using WHOIS\
- Saves results in a CSV file

**Installation & Usage**

 1. Clone the repository:

```bash
git clone https://github.com/yourusername/phishing-url-scanner.git
cd phishing-url-scanner
```

2. Install dependencies:
```bash

pip install requests python-whois
```

3. Run the script:

python phishing_scanner.py

**Contributing**

Contributions are welcome! If you have suggestions or improvements, feel free to fork the repository and submit a pull request.

**License**
This project is licensed under the MIT License - see the LICENSE file for details.







