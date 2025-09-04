from elasticsearch import Elasticsearch
from datetime import datetime

# Connect to Elasticsearch
es = Elasticsearch([{'host': 'localhost', 'port': 9200}])

# Query for suspicious login attempts
query = {
  "query": {
    "match": {
      "alert": "Suspicious Login Attempt"
    }
  }
}

# Fetch data from Elasticsearch
response = es.search(index="security-logs", body=query)

# Generate the report
def generate_report(response):
    report = f"Incident Response Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += "=" * 50 + "\n"
    report += "Suspicious Login Attempts:\n"

    for hit in response['hits']['hits']:
        timestamp = hit['_source']['@timestamp']
        message = hit['_source']['message']
        report += f"Timestamp: {timestamp}, Message: {message}\n"

    report += "=" * 50 + "\n"
    report += "Recommendations:\n"
    report += "- Review failed login attempts and block suspicious IPs.\n"
    report += "- Enable multi-factor authentication (MFA) for all users.\n"
    report += "- Review system logs regularly for any unusual activities.\n"

    return report

# Generate and save the report
report = generate_report(response)
with open("incident_response_report.txt", "w") as file:
    file.write(report)

print("Incident response report generated.")
