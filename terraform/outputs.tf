output "vm_internal_ip" {
  value       = google_compute_instance.soc_lab_vm.network_interface[0].network_ip
  description = "Internal IP of the SOC lab VM"
}

output "vm_external_ip" {
  value       = google_compute_instance.soc_lab_vm.network_interface[0].access_config[0].nat_ip
  description = "External IP of the SOC lab VM"
}

output "pubsub_topic" {
  value       = google_pubsub_topic.cloud_siem_events.id
  description = "Pub/Sub topic for SIEM events"
}
