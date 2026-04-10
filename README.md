# PhishHawk 🦅

> Open source phishing analysis IOC extraction pipeline for threat intelligence analysts. 
> PhishHawk automates the manual workflow of phishing investigation - from raw `.eml`file to structured threat report. It extracts IOC's, enriches them against multiple threat intelligence sources, and exports results in formats compatible with common TI workflows. 
> Built for analysts who don't have an entire SOC team behind them.

---

## Features

- **EML Parser** - extracts IP's, domains, URL's, and sender data from email headers and body
- **Enrichment Engine** - automatically queries whois, DNS, crt.sh, AbuseIPDB, and URLScan
- **Raw Mode** - works without and AI/LLM API key, outoputs structured data directly
- **BYOK LLM** - bring your own API key for AI-assisted correlation and report generation (Anthropic, OpenAI, Ollama)
- **Multiple output formats** - JSON, CSV, defanged IOC list

---

## Roadmap

| Milestone | Status | Description |
|---|---|---|
| M1 — Core Pipeline | ✅ Complete | Parser + enrichment + raw output |
| M2 — Enrichment & Output | 🔄 Planned | AI correlation, MISP/STIX export, report generation |

---

## Installation

```bash
git clone https://github.com/LauritsCSB/phishHawk.git
cd phishhawk
python3 -m venv .venv
source .venv/bin/activate
pip install -e
```

---

## Configuration

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml` with your API keys:

```yaml
enrichment:
    abuseipdb_api_key: "YOUR_ABUSEIPDB_API_KEY"
    urlscan_api_key: "YOUR_URLSCAN_API_KEY"

llm:
    provider: "anthropic" #anthropic, openai or ollama
    api_key: "YOUR_API_KEY"
    model: "claude-sonnet-4-20250514"

output:
    format: "markdown"
    defang: true
    output_dir: "./reports"
```

---

## Usage

```bash
# Coming in M2
```

---

## Output Formats

| Format | Description |
|---|---|
| JSON | Full enriched dataset, machine-readable |
| CSV | Flat IOC list for spreadsheet tools |
| TXT | Defanged IOC list for safe sharing |
| Markdown | Human-readable threat report (M2) |
| STIX/TAXII | Compatible with MISP and TI platforms (M2) |

---

## Architetecture

.eml input
└── Parser → extracts IOCs
└── Enrichment → whois, DNS, crt.sh, AbuseIPDB, URLScan
└── Output → JSON, CSV, defanged IOC list
└── AI Layer (M2) → correlation, MITRE mapping, report

---

## API Keys

| Service | Free Tier | Required |
|---|---|---|
| AbuseIPDB | 1,000 requests/day | Yes |
| URLScan.io | 5,000 scans/month | Yes |
| VirusTotal | 500 requests/day | No |
| Anthropic / OpenAI / Ollama | Varies | No (raw mode available) |

---

## License

MIT - free to use, modify, and distribute.

---

## Author

Built by Laurits Bentsen (LinkedIn: www.linkedin.com/in/laurits-bentsen-311491a8) as par of a career transition from paramedicine til cybersecurity.