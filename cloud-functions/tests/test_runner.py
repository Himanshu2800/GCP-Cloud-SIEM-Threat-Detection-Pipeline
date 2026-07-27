{
  "test_name": "GCP VM Instance Deleted",
  "event": {
    "eventType": "compute.instances.delete",
    "resourceType": "gce_instance",
    "principalEmail": "attacker@example.com",
    "...": "whatever your normalized schema has"
  },
  "expected": {
    "rule_triggered": "GCP VM Instance Deleted",
    "mitre_technique": "T1485",
    "should_alert": true
  }
}
