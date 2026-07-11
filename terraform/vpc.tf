resource "google_compute_network" "soc_lab_vpc" {
  name                    = "soc-lab-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "soc_subnet" {
  name          = "soc-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.soc_lab_vpc.id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
