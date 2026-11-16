resource "google_compute_instance" "soc_lab_vm" {
  name         = "soc-lab-vpc"
  machine_type = "e2-medium"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 50
    }
  }

  network_interface {
    network    = google_compute_network.soc_lab_vpc.id
    subnetwork = google_compute_subnetwork.soc_subnet.id

    access_config {
      // Ephemeral public IP
    }
  }

  metadata_startup_script = <<-EOT
    #!/bin/bash
    set -eu
    umask 077
    apt-get update
    apt-get install -y docker.io openssl
    systemctl start docker
    systemctl enable docker

    # Generate once per VM and reuse on subsequent boots. Never print the secret.
    install -d -m 700 /opt/opensearch
    if [ ! -s /opt/opensearch/admin.env ]; then
      generated_password=$(openssl rand -hex 32)
      printf 'OPENSEARCH_INITIAL_ADMIN_PASSWORD=Aa1!%s\n' "$generated_password" > /opt/opensearch/admin.env
    fi
    chmod 600 /opt/opensearch/admin.env

    # Run OpenSearch
    docker run -d \
      --name opensearch-node1 \
      -p 9200:9200 \
      -p 9600:9600 \
      -e "discovery.type=single-node" \
      --env-file /opt/opensearch/admin.env \
      opensearchproject/opensearch:latest

    # Run OpenSearch Dashboards
    docker run -d \
      --name opensearch-dashboards \
      -p 5601:5601 \
      -e "OPENSEARCH_HOSTS=https://opensearch-node1:9200" \
      opensearchproject/opensearch-dashboards:3.7.0

    # Run Grafana
    docker run -d \
      --name grafana \
      -p 3000:3000 \
      -e GF_INSTALL_PLUGINS=grafana-opensearch-datasource \
      grafana/grafana:latest
  EOT

  service_account {
    scopes = ["cloud-platform"]
  }
}
