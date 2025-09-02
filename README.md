# Government Website Privacy Analysis
This repository contains the code and data for the paper "Analysis of Government-Sponsored Technology (Mis)use" (Master Thesis, Universidad Carlos III de Madrid 2025).

## Abstract
Analysis of 215 government websites across 7 countries revealing compliance failures and tracking practices.

## Repository Structure
├── data/              # Aggregated metrics and processed datasets by country
│   ├── chile/
│   ├── mexico/
│   ├── spain/
│   ├── australia/
│   ├── india/
│   ├── united-kingdom/
│   └── south-africa/
├── code/              # Python scripts for data collection and analysis
├── notebooks/         # Jupyter notebooks for analysis and visualization
└── figures/           # Generated figures used in the paper

## Dataset Description
### Countries Analyzed
- 🇪🇸 Spain (95 domains)
- 🇬🇧 United Kingdom (20 domains)
- 🇲🇽 Mexico (20 domains)
- 🇨🇱 Chile (20 domains)
- 🇦🇺 Australia (20 domains)
- 🇿🇦 South Africa (20 domains)
- 🇮🇳 India (20 domains)

## Key Findings
- **27.4%** average compliance score for Spain despite GDPR
- **>50%** tracker presence across all countries
- **77.8%** of Spanish sites violate international transfer declarations
- **0%** cookie policies in non-European countries

## Methodology
### Technical Stack
- **OpenWPM** - Browser automation and tracking detection
- **SSLyze** - TLS/SSL security scanning
- **Playwright** - Fingerprinting detection
- **Gemini** - Privacy policy extraction

### Analysis Pipeline
1. Domain discovery via Certificate Transparency logs
2. Technical measurements (cookies, trackers, security headers)
3. Privacy policy extraction and analysis
4. Compliance verification against declared practices

## Usage
```bash
# Clone repository
git clone https://github.com/inespalero/gov-privacy-analysis.git
cd gov-privacy-analysis

# Install dependencies
pip install -r code/requirements.txt

# Stage 1: Domain Discovery
python code/collect_gov_domains.py # Edit default country suffixes if desired

# Stage 2: Domain Accessibility Check
python code/check_domains.py files (txt domains)

# Stage 3: Technical Crawling
python code/crawl_openwpm.py --input (txt domains) --outdir (Output directory)
# Output: OpenWPM database

# Stage 4: TLS Security Scanning
python code/tls_scan.py --input (txt domains)
# Output: json files + csv summary

python code/parse_tls_json.py --indir (tls directory) --out (Output file)
# Output: csv flat tls

# Stage 5: Fingerprinting Detection
python code/fp_scan.py --input (txt domains)
# Output: json files + csv summary

python code/parse_fp_summary.py --summary (csv summary) --out (Output file)
# Output: csv flat fp

#Stage 6: Extract Technical Metrics
# Extract cookies
python code/extract_cookies.py --sqlite (database) --out (Output file)
# Output: csv cookies

# Extract HTTP Requests
python code/extract_requests.py --sqlite (database) --out (Output file)
# Output: csv requests

# Extract Security Headers
python code/extract_sec_headers.py --sqlite (database) --out (Output file) --requests (csv requests)
# Output: csv sec_headers

# Stage 7: Tracker Enrichment
python code/enrich_trackers.py --input (csv cookies) --maping (TrackerRadar file) --out (Output file)
# Output: csv cookies_enriched
python code/enrich_trackers.py --input (csv requests) --maping (TrackerRadar file) --out (Output file)
# Output: csv requests_enriched

# Stage 8: Build Master Dataset
python code/build_master_dataset.py --cookies (csv cookies_enriched) --requests (csv requests_enriched) --headers (csv sec_headers) --tls_flat (csv flat tls) --fp_flat (csv flat fp) --official (txt domains)--out (Output file)
# Output: csv master_dataset

# Stage 9: Policy Discovery
python code/discover_policies.py --domains (txt domains) --out (Output file) 
# Output: json links

# Stage 10: Policy Analysis
python code/analyse_policiesFINAL.py --links (json links) --out (Output file)
# Output: json documents

# Stage 11: Aggregate domains
python code/aggregate_domains.py --src (json documents)--dst (Output file)
# Output: csv aggregate_domains

# Stage 12: Compliance Check
python code/compliance_check.py --policies (json documents) --domains (csv aggregate_domains) --tech (csv master_dataset) --out (Output file)
# Output: csv compliance

# Stage 13: Generate Final Metrics
python code/tfm_metrics.py --data-dir (Input directory) --out-dir (Output directory)
# Output: Printed summary + json aggregated_metrics

# Visualization
jupyter notebook notebooks/generate_figures.ipynb

```

## Important Notes
- API Keys: Gemini API key required for policy analysis
- Browser: Firefox required for OpenWPM
- Network: Stable connection needed for crawling

## Ethics Statement
All data was collected from publicly accessible websites following robots.txt policies. No authentication or personal data was collected.

## License
CC BY-NC-SA 4.0 License - See LICENSE file

## Contact
For questions or raw data requests: 100538264@alumnos.uc3m.es (Inés Palero San Román)

## Citation
If you use this dataset in your research, please cite:

@mastersthesis{palero2025government,
  title={Analysis of Government-Sponsored Technology (Mis)use},
  author={Palero San Román, Inés},
  year={2025},
  school={Universidad Carlos III de Madrid},
  type={Master's Thesis}
}
