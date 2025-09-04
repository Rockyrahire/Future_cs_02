Security Alert Monitoring & Incident Response

This project implements a Security Information and Event Management (SIEM) system using Elastic Stack (ELK) to monitor simulated security alerts, identify suspicious activities, classify incidents, and draft an incident response report.

Table of Contents

Overview

Setup Instructions

Log Parsing with Logstash

Alerting and Incident Detection

Incident Response Report

Project Deliverables

Contributions

Overview

In this project, we leverage the Elastic Stack (ELK) for monitoring and analyzing security logs. The primary objective is to process and classify security events like failed login attempts, invalid users, and other suspicious activities. The system generates alerts for these incidents, and an automated report is generated for incident response.

The key components of this system are:

ElasticSearch: Stores and indexes logs.

Logstash: Processes raw logs and sends them to Elasticsearch.

Kibana: Visualizes the data and allows querying of the logs.

Python: Used for generating automated incident response reports.

Setup Instructions
1. Install Elasticsearch, Logstash, and Kibana (ELK Stack)

You can follow the installation guide from the official Elastic documentation
 to set up the ELK Stack.

Alternatively, you can use Docker for easy setup:

# Start Elasticsearch, Logstash, and Kibana using Docker
docker-compose up -d


Ensure that Elasticsearch is running on http://localhost:9200, Logstash on http://localhost:5044, and Kibana on http://localhost:5601.

2. Configure Logstash

Create a Logstash configuration file logstash.conf in the Logstash configuration directory to filter and parse log data.

Example configuration for monitoring authentication logs:

input {
  file {
    path => "/var/log/auth.log"  # Path to your system logs
    start_position => "beginning"
    sincedb_path => "/dev/null"  # For testing
  }
}

filter {
  if [message] =~ "Failed password" {
    mutate { add_field => { "alert" => "Suspicious Login Attempt" } }
  }

  if [message] =~ "Invalid user" {
    mutate { add_field => { "alert" => "Invalid User Attempt" } }
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "security-logs"
  }

  file {
    path => "/tmp/logstash_output.log"
  }
}

3. Running Logstash

Start Logstash with the following command to begin ingesting logs:

logstash -f logstash.conf

4. Set Up Kibana Dashboards

In Kibana, you can create visualizations to monitor the alerts:

Access Kibana at http://localhost:5601.

Create an Index Pattern for the security-logs index.

Use Dashboards to create visualizations for failed logins and suspicious activity.

5. Set Up Alerting in Elasticsearch

You can create automated alerts using Watcher (in older versions) or Alerting (in newer versions) in Elasticsearch to notify you when suspicious activity is detected. For example, use the following configuration for failed login attempts:

{
  "trigger": {
    "schedule": {
      "interval": "10m"
    }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["security-logs"],
        "body": {
          "query": {
            "match": {
              "alert": "Suspicious Login Attempt"
            }
          },
          "size": 0
        }
      }
    }
  },
  "condition": {
    "compare": {
      "input.payload.hits.total.value": {
        "gt": 10
      }
    }
  },
  "actions": {
    "notify_email": {
      "email": {
        "to": ["security_team@example.com"],
        "subject": "High Number of Failed Logins Detected",
        "body": "More than 10 failed login attempts in the last 10 minutes."
      }
    }
  }
}

6. Generate Incident Response Report Using Python

Use Python to generate an automated incident response report based on the logs stored in Elasticsearch. Install the required library:

pip install elasticsearch


Run the Python script incident_report.py to query Elasticsearch and generate a report:

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

7. Save the Report

This script will output an incident response report to incident_response_report.txt with the following sections:

Suspicious activity (failed logins, invalid users).

Timestamp and log message details.

Recommendations for mitigation and next steps.

Project Deliverables

Incident Response Report generated by the Python script.

ELK Stack Setup including Logstash, Elasticsearch, and Kibana for monitoring and analyzing logs.

Alert Configuration to notify users of suspicious activities like failed login attempts.

Contributions

Feel free to contribute to the project by forking the repository, creating issues, and submitting pull requests.

License

This project is licensed under the MIT License - see the LICENSE
 file for details.

This README.md provides an overview of the steps involved in the task, setup instructions, and how to interact with the system to monitor, alert, and respond to security incidents using the Elastic Stack (ELK). Let me know if you need further modifications or additions to this document! Future_cs_02
