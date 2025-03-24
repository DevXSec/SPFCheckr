# SPFCheckr

🚀 SPFGuard – A Simple Yet Powerful SPF Record Checker

SPFGuard is a lightweight and efficient SPF (Sender Policy Framework) validation tool that helps verify if an IP address is authorized to send emails on behalf of a domain. This tool is ideal for email security analysis, ensuring that your mail server configurations align with SPF authentication best practices.

✨ Features
🔍 SPF Record Lookup – Fetches and parses SPF records for any domain.

✅ IP Authorization Check – Validates if a sender’s IP is allowed by the SPF policy.

📊 Detailed Analysis – Extracts included domains, IPs, mx, a and policies (+all, -all, ~all, ?all).

🔧 Easy to Use – Simple PHP-based implementation with minimal dependencies.

📦 Installation & Usage

Clone the repository:
```
git clone https://github.com/DevXSec/SPFCheckr.git
cd SPFGuard
```

Run the script:
```
php check_spf.php yourdomain.com
```

📜 License
MIT License – Open-source and free to use.
