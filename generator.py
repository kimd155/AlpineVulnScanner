from jinja2 import Template
from datetime import datetime

def generate_report(package_name, package_version, vulnerabilities):
    now = datetime.now()
    timestamp = now.strftime('%H:%M %d/%m/%Y')

    template = Template(open("template.html").read())
    report = template.render(package_name=package_name, package_version=package_version, vulnerabilities=vulnerabilities, timestamp=timestamp)

    with open(f'{package_name}_vulnerability_report.html', 'w') as f:
        f.write(report)
