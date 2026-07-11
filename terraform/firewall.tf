resource "google_compute_firewall" "allow_opensearch_from_cloudrun" {
  name    = "allow-opensearch-from-cloudrun"
  network = google_compute_network.soc_lab_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["9200"]
  }

  source_ranges = ["10.0.0.0/24"]
  direction     = "INGRESS"
}

resource "google_compute_firewall" "allow_grafana" {
  name    = "allow-grafana"
  network = google_compute_network.soc_lab_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["3000"]
  }

  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"
}

resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh"
  network = google_compute_network.soc_lab_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"
}
