import requests

def extract_cvss_score(vuln):
    metrics = vuln['cve'].get('metrics', {})
    if 'cvssMetricV31' in metrics:
        return metrics['cvssMetricV31'][0]['cvssData']['baseScore']
    elif 'cvssMetricV30' in metrics:
        return metrics['cvssMetricV30'][0]['cvssData']['baseScore']
    elif 'cvssMetricV2' in metrics:
        return metrics['cvssMetricV2'][0]['cvssData']['baseScore']
    else:
        return "N/A"

def query_nvd(package_name, package_version, api_key):
    headers = {'apiKey': api_key}
    vulnerabilities = []
    
    search_term = f"{package_name} {package_version.split('-')[0]}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}"
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json().get('vulnerabilities', [])
        
        for vuln in result:
            vuln['cvss_score'] = extract_cvss_score(vuln)
            vulnerabilities.append(vuln)
        
        print(f"\nNVD API Response for Keyword: {search_term}\nTotal Results: {len(result)}\n")
        
    except requests.RequestException as e:
        print(f"Error querying NVD API with keyword '{search_term}': {e}")
    
    return vulnerabilities
