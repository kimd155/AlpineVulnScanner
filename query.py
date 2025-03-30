import requests
from packaging import version

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

def is_version_affected(description, current_version):
    current_ver = version.parse(current_version)
    description = description.lower()
    
    if any(keyword in description for keyword in ["before", "up to", "prior to", "<=", "<"]):
        if "before" in description or "up to" in description or "prior to" in description:
            words = description.split()
            for i, word in enumerate(words):
                if word in ["before", "up to", "prior to"]:
                    try:
                        affected_version = version.parse(words[i + 1].strip(",.;)"))
                        if current_ver < affected_version:
                            return True
                        else:
                            return False
                    except:
                        continue

        if "<=" in description or "<" in description:
            words = description.split()
            for i, word in enumerate(words):
                if word.startswith("<=") or word.startswith("<"):
                    try:
                        affected_version = version.parse(word.strip(",.;)<>="))
                        if current_ver <= affected_version if "<=" in word else current_ver < affected_version:
                            return True
                        else:
                            return False
                    except:
                        continue
    
    if any(keyword in description for keyword in ["starting from", ">= ", ">", "and later", "after"]):
        if "starting from" in description or "and later" in description or "after" in description:
            words = description.split()
            for i, word in enumerate(words):
                if word in ["starting from", "and later", "after"]:
                    try:
                        affected_version = version.parse(words[i + 1].strip(",.;)"))
                        if current_ver >= affected_version:
                            return True
                        else:
                            return False
                    except:
                        continue

        if ">=" in description or ">" in description:
            words = description.split()
            for i, word in enumerate(words):
                if word.startswith(">=") or word.startswith(">"):
                    try:
                        affected_version = version.parse(word.strip(",.;)>=<"))
                        if current_ver >= affected_version if ">=" in word else current_ver > affected_version:
                            return True
                        else:
                            return False
                    except:
                        continue
    
    return False

def query_nvd(package_name, package_version, api_key):
    headers = {'apiKey': api_key}
    vulnerabilities = []
    current_version = package_version.split('-')[0]

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={package_name}&resultsPerPage=2000"
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        all_results = response.json().get('vulnerabilities', [])
        
    except requests.RequestException as e:
        print(f"Error fetching vulnerabilities for '{package_name}': {e}")
        return vulnerabilities

    for vuln in all_results:
        cve_id = vuln['cve']['id']
        descriptions = vuln['cve']['descriptions']
        cvss_score = extract_cvss_score(vuln)
        affected_versions = []
        version_found_in_description = False

        for description in descriptions:
            desc_text = description['value']
            if is_version_affected(desc_text, current_version):
                version_found_in_description = True
                break

        if version_found_in_description:
            vulnerabilities.append({
                'cve': vuln['cve'],
                'cvss_score': cvss_score,
                'version_found_in_description': version_found_in_description,
                'description': desc_text
            })

    print(f"\nNVD API Response for '{package_name}'\nTotal Matching Results: {len(vulnerabilities)}\n")
    return vulnerabilities
