import os
import sys
from extractor import extract_metadata
from query import query_nvd
from generator import generate_report

def main():
    if len(sys.argv) != 3:
        print("Usage: python main.py <path_to_apk> <api_key>")
        sys.exit(1)

    apk_path = sys.argv[1]
    api_key = sys.argv[2]

    if not os.path.isfile(apk_path):
        print("Invalid APK file path.")
        sys.exit(1)

    metadata = extract_metadata(apk_path)
    vulnerabilities = query_nvd(metadata['name'], metadata['version'], api_key)
    generate_report(metadata['name'], metadata['version'], vulnerabilities)

    print(f"Report generated: {metadata['name']}_vulnerability_report.html")

if __name__ == "__main__":
    main()