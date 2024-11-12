import requests
import feedparser
import os
from datetime import datetime

# Define the RSS feeds and keywords for each source
rss_sources = {
    "CyberScoop": {
        "url": "https://cyberscoop.com/news/financial/feed/",
        "keywords": ["finance", "bank", "ransomware", "CrowdStrike", "Business", "Regulation", "Cybercrime"]
    },
    "ThreatPost": {
        "url": "https://threatpost.com/feed/",
        "keywords": ["cybercriminal", "hacktivist", "vulnerabilities", "cyberterrorism", "Zero-Day", "Bug", "Malware", "Government"]
    },
    "ExploitDB": {
        "url": "https://www.exploit-db.com/rss.xml",
        "keywords": ["Authentication", "DNS", "SolarWinds", "SQL", "XSS", "Syslogs", "FreePBX", "0day"]
    }
}

# Fetch API key
api_key = os.getenv("OTX_API_KEY")
print(api_key)
if not api_key:
    raise ValueError("API key not found. Please set the OTX_API_KEY environment variable.")

# Fetch and filter RSS feed entries based on keywords
def fetch_and_filter_rss(url, keywords):
    feed = feedparser.parse(url)
    filtered_entries = [
        entry for entry in feed.entries
        if any(keyword.lower() in entry.title.lower() or keyword.lower() in entry.description.lower() for keyword in keywords)
    ]
    return filtered_entries[:10]  # Limit to top 10 entries

# Clean and format titles and dates for HTML
def clean_exploitdb_title(title):
    return title.split("] ", 1)[1] if title.startswith("[") and "] " in title else title

def format_published_date(published):
    return published.replace(" +0000", "").replace("00:00:00", "").strip()

# Fetch data from AlienVault and populate lists
def fetch_alienvault_data():
    headers = {"X-OTX-API-KEY": api_key}
    
    # Initialize lists for indicators
    ssh_Ioc = []
    docker_Ioc = []
    smb_Ioc = []
    phis_Ioc = []
    md5_hashes = []
    sha1_hashes = []
    sha256_hashes = []
    
    # Define pulses and types
    pulses = {
        "SSH Brute-Force": {"id": "60ece5998a5b54a5ffe75cb4", "type": "IPv4", "variable": "ssh_Ioc"},
        "Docker API Exploit Attempts": {"id": "66c74422b99d3b24bb2c574b", "type": "IPv4", "variable": "docker_Ioc"},
        "SMB Brute-Force": {"id": "6731d9df3237af17724afe5e", "type": "IPv4", "variable": "smb_Ioc"},
        "Phishing URLs": {"id": "60a794fa6de6293139323f21", "type": "URL", "variable": "phis_Ioc"}
    }
    
    # Fetch data for each pulse
    for pulse_name, pulse_info in pulses.items():
        pulse_id = pulse_info["id"]
        indicator_type = pulse_info["type"]
        response = requests.get(f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}", headers=headers)
        indicators = [indicator["indicator"] for indicator in response.json().get("indicators", []) if indicator.get("type") == indicator_type]
        if pulse_info["variable"] == "ssh_Ioc":
            ssh_Ioc.extend(indicators)
        elif pulse_info["variable"] == "docker_Ioc":
            docker_Ioc.extend(indicators)
        elif pulse_info["variable"] == "smb_Ioc":
            smb_Ioc.extend(indicators)
        elif pulse_info["variable"] == "phis_Ioc":
            phis_Ioc.extend(indicators)
    
    # Fetch hashes from subscribed data
    subscribed_url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=100"
    response = requests.get(subscribed_url, headers=headers)
    for result in response.json().get("results", []):
        for indicator in result.get("indicators", []):
            if indicator.get("type") == "FileHash-MD5":
                md5_hashes.append(indicator.get("indicator"))
            elif indicator.get("type") == "FileHash-SHA1":
                sha1_hashes.append(indicator.get("indicator"))
            elif indicator.get("type") == "FileHash-SHA256":
                sha256_hashes.append(indicator.get("indicator"))
    
    return ssh_Ioc, docker_Ioc, smb_Ioc, phis_Ioc, md5_hashes, sha1_hashes, sha256_hashes

def generate_html(filtered_data, ssh_Ioc, docker_Ioc, smb_Ioc, phis_Ioc, md5_hashes, sha1_hashes, sha256_hashes):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    html_content = f"""
    <html>
    <head>
        <title>La veille sur les cybermenaces</title>
        <link rel="stylesheet" type="text/css" href="styles.css">
        <style>
            .dashboard-table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }}
            .dashboard-table th, .dashboard-table td {{
                border: 1px solid #ddd;
                padding: 8px;
                vertical-align: top;
            }}
            .dashboard-table th {{
                background-color: #333;
                color: #fff;
                font-weight: bold;
                text-align: center;
            }}
            .list-container {{
                max-height: 150px;
                overflow-y: auto;
                padding: 5px;
                border: 1px solid #ddd;
                margin-top: 10px;
            }}
            .copy-button {{
                margin-top: 5px;
                font-size: small;
            }}
        </style>
        <script>
            function copyToClipboard(text) {{
                navigator.clipboard.writeText(text);
                alert('Copied to clipboard!');
            }}
        </script>
    </head>
    <body>
        <h1>La veille sur les cybermenaces - Dernière mise à jour: {current_time}</h1>
        
        <!-- RSS Feed Section -->
        <h2>Flux RSS</h2>
        <table class="dashboard-table">
            <tr>
                <th>ThreatPost</th>
                <th>CyberScoop</th>
                <th>ExploitDB</th>
            </tr>
            <tr>
    """
    
    # RSS Feed Data
    for source in ["CyberScoop", "ThreatPost", "ExploitDB"]:
        html_content += "<td><ul>"
        for entry in filtered_data[source]:
            title = clean_exploitdb_title(entry.title) if source == "ExploitDB" else entry.title
            published_date = format_published_date(entry.published) if 'published' in entry else 'Date not available'
            html_content += f"<li><a href='{entry.link}'>{title}</a> - {published_date}</li>"
        html_content += "</ul></td>"
    
    html_content += """
            </tr>
        </table>

        <!-- Malicious IP Address and Domain Section -->
        <h2>Adresses IP et domaines Web malveillants</h2>
        <table class="dashboard-table">
            <tr>
                <th>SSH Brute-Force</th>
                <th>Docker API Exploit</th>
                <th>SMB Brute-Force</th>
            </tr>
            <tr>
                <td>
                    <div class="list-container" style="max-height: 150px; overflow-y: auto; overflow-wrap: break-word; word-break: break-all; padding: 10px;">
                        """ + "<br>".join(ssh_Ioc) + """
                    </div>
                    <button class="copy-button" onclick="copyToClipboard('""" + "\n".join(ssh_Ioc) + """')">Copy</button>
                </td>
                <td>
                    <div class="list-container" style="max-height: 150px; overflow-y: auto; overflow-wrap: break-word; word-break: break-all; padding: 10px;">
                        """ + "<br>".join(docker_Ioc) + """
                    </div>
                    <button class="copy-button" onclick="copyToClipboard('""" + "\n".join(docker_Ioc) + """')">Copy</button>
                </td>
                <td>
                    <div class="list-container" style="max-height: 150px; overflow-y: auto; overflow-wrap: break-word; word-break: break-all; padding: 10px;">
                        """ + "<br>".join(smb_Ioc) + """
                    </div>
                    <button class="copy-button" onclick="copyToClipboard('""" + "\n".join(smb_Ioc) + """')">Copy</button>
                </td>
            </tr>
            <tr>
                <th colspan="3">Phishing URLs</th>
            </tr>
            <tr>
                <td colspan="3">
                    <div class="list-container" style="max-height: 150px; overflow-y: auto; overflow-wrap: break-word; word-break: break-all; padding: 10px;">
                        """ + "<br>".join(phis_Ioc) + """
                    </div>
                    <button class="copy-button" onclick="copyToClipboard('""" + "\n".join(phis_Ioc) + """')">Copy</button>
                </td>
            </tr>
        </table>

        <!-- Malicious Hashes Section -->
        <h2>Hachages de fichiers malveillants</h2>
        <table class="dashboard-table">
            <tr>
                <th>MD5</th>
                <th>SHA1</th>
                <th>SHA256</th>
            </tr>
            <tr>
                <td>
                    <div class="list-container">""" + "<br>".join(md5_hashes) + """</div>
                    <button class="copy-button" onclick="copyToClipboard('""" + "\n".join(md5_hashes) + """')">Copy</button>
                </td>
                <td>
                    <div class="list-container">""" + "<br>".join(sha1_hashes) + """</div>
                    <button class="copy-button" onclick="copyToClipboard('""" + "\n".join(sha1_hashes) + """')">Copy</button>
                </td>
                <td>
                    <div class="list-container">""" + "<br>".join(sha256_hashes) + """</div>
                    <button class="copy-button" onclick="copyToClipboard('""" + "\n".join(sha256_hashes) + """')">Copy</button>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    # Write the HTML content to a file
    with open("index.html", "w") as f:
        f.write(html_content)

# Fetch and filter data for each RSS source
filtered_data = {source: fetch_and_filter_rss(config["url"], config["keywords"]) for source, config in rss_sources.items()}

# Fetch data for AlienVault indicators
ssh_Ioc, docker_Ioc, smb_Ioc, phis_Ioc, md5_hashes, sha1_hashes, sha256_hashes = fetch_alienvault_data()

# Generate the HTML page
generate_html(filtered_data, ssh_Ioc, docker_Ioc, smb_Ioc, phis_Ioc, md5_hashes, sha1_hashes, sha256_hashes)
