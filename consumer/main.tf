# -------------------------------------------------------------------------------------
# Provider configuration
# -------------------------------------------------------------------------------------

terraform {
  required_version = "> 1.5, < 2.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.50" # Back to where you were
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.50" # Add the beta provider at the same version
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.38"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.8"
    }
  }
}

provider "google" {
  project               = var.project_id
  region                = var.region
  billing_project       = var.billing_project_id
  user_project_override = true
  default_labels = {
    panw = "true"
  }
}

provider "google-beta" {
  project               = var.project_id
  region                = var.region
  billing_project       = var.billing_project_id
  user_project_override = true
  default_labels = {
    panw = "true"
  }
}

# -------------------------------------------------------------------------------------
# Localized variables
# -------------------------------------------------------------------------------------

locals {
  prefix                   = var.prefix != null && var.prefix != "" ? "${var.prefix}-" : ""
  gke_subnet_cidr_cluster  = "10.20.0.0/16"
  gke_subnet_cidr_services = "10.30.0.0/16"
  gke_version              = "1.28"
}


# -------------------------------------------------------------------------------------
# Create VPC network and Cloud NAT.
# -------------------------------------------------------------------------------------

// Create consumer VPC
resource "google_compute_network" "main" {
  name                    = "${local.prefix}consumer-vpc"
  auto_create_subnetworks = false
}

// Create consumer subnetwork
resource "google_compute_subnetwork" "main" {
  name          = "${local.prefix}${var.region}-consumer"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.main.id

  secondary_ip_range {
    range_name    = "${local.prefix}${var.region}-cluster"
    ip_cidr_range = local.gke_subnet_cidr_cluster
  }

  secondary_ip_range {
    range_name    = "${local.prefix}${var.region}-services"
    ip_cidr_range = local.gke_subnet_cidr_services
  }
}

// Allow external access from var.mgmt_allow_ips
resource "google_compute_firewall" "external" {
  name          = "${local.prefix}consumer-allow-external"
  network       = google_compute_network.main.name
  source_ranges = var.mgmt_allow_ips

  allow {
    protocol = "tcp"
    ports    = ["80", "22"]
  }
}

// Allow all intra-VPC traffic within the consumer VPC
resource "google_compute_firewall" "local" {
  name          = "${local.prefix}consumer-allow-local"
  network       = google_compute_network.main.name
  source_ranges = [var.subnet_cidr]

  allow {
    protocol = "all"
    ports    = []
  }
}

// Create cloud router for cloud NAT.
resource "google_compute_router" "main" {
  name    = "${local.prefix}${var.region}-consumer-router"
  region  = var.region
  network = google_compute_network.main.id
}

// Create cloud NAT for outbound internet access.
resource "google_compute_router_nat" "main" {
  name                               = "${local.prefix}${var.region}-consumer-nat"
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}



# -------------------------------------------------------------------------------------
# Create web & client VMs
# -------------------------------------------------------------------------------------

data "google_compute_zones" "available" {
  region = var.region
}

resource "google_compute_instance" "client" {
  name                      = "${local.prefix}client-vm"
  machine_type              = "f1-micro"
  zone                      = data.google_compute_zones.available.names[0]
  can_ip_forward            = false
  allow_stopping_for_update = true
  tags                      = ["client-vm"]
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id
    network_ip = cidrhost(var.subnet_cidr, 10)
  }

  metadata = {
    serial-port-enable = true
  }

  metadata_startup_script = <<SCRIPT
    #! /bin/bash 
    apt-get update 
    apt-get install apache2-utils mtr iperf3 tcpdump -y
    SCRIPT

  service_account {
    scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }

  depends_on = [
    google_compute_router_nat.main
  ]
}

resource "google_compute_instance" "web" {
  name                      = "${local.prefix}web-vm"
  machine_type              = "f1-micro"
  zone                      = data.google_compute_zones.available.names[0]
  can_ip_forward            = false
  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id
    network_ip = cidrhost(var.subnet_cidr, 20)
  }

  metadata = {
    serial-port-enable = true
  }

  metadata_startup_script = <<SCRIPT
    #! /bin/bash 
    sudo apt-get update
    sudo apt-get install coreutils -y
    sudo apt-get install php -y
    sudo apt-get install apache2 tcpdump iperf3 -y 
    sudo a2ensite default-ssl 
    sudo a2enmod ssl 
    # Apache configuration:
    sudo rm -f /var/www/html/index.html
    sudo wget -O /var/www/html/index.php https://raw.githubusercontent.com/wwce/terraform/master/azure/transit_2fw_2spoke_common/scripts/showheaders.php 
    systemctl restart apache2
    SCRIPT

  service_account {
    scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }

  depends_on = [
    google_compute_router_nat.main
  ]
}



# -------------------------------------------------------------------------------------
# Create GKE cluster
# -------------------------------------------------------------------------------------

module "gke" {
  source                      = "terraform-google-modules/kubernetes-engine/google"
  version                     = "36.1.0"
  project_id                  = var.project_id
  name                        = "${local.prefix}cluster1"
  regional                    = false
  region                      = var.region
  zones                       = ["${data.google_compute_zones.available.names[0]}"]
  network                     = google_compute_network.main.name
  subnetwork                  = google_compute_subnetwork.main.name
  ip_range_pods               = google_compute_subnetwork.main.secondary_ip_range[0].range_name
  ip_range_services           = google_compute_subnetwork.main.secondary_ip_range[1].range_name
  release_channel             = "UNSPECIFIED"
  create_service_account      = true
  http_load_balancing         = true
  network_policy              = false
  horizontal_pod_autoscaling  = false
  deletion_protection         = false
  enable_intranode_visibility = true # Must be enabled for pod-to-pod traffic mirroring to SW-NGFW.

  node_pools = [
    {
      name               = "default-node-pool"
      machine_type       = "e2-standard-2"
      initial_node_count = 1
      auto_upgrade       = true
    }
  ]

  node_pools_oauth_scopes = {
    all = []
    default-node-pool = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}

data "google_container_cluster" "main" {
  name     = module.gke.name
  location = data.google_compute_zones.available.names[0]
}


# -------------------------------------------------------------------------------------
#  If mirroring_deployment = false, create intercept deployment.
# -------------------------------------------------------------------------------------

// Create intercept endpoint group
resource "google_network_security_intercept_endpoint_group" "main" {
  count                       = var.mirroring_deployment ? 0 : 1
  intercept_endpoint_group_id = "${local.prefix}panw-epg"
  location                    = "global"
  intercept_deployment_group  = var.producer_dg
}

// Create intercept endpoint association
resource "google_network_security_intercept_endpoint_group_association" "main" {
  count                                   = var.mirroring_deployment ? 0 : 1
  intercept_endpoint_group_association_id = "${local.prefix}panw-epg-assoc"
  location                                = "global"
  network                                 = google_compute_network.main.id
  intercept_endpoint_group                = google_network_security_intercept_endpoint_group.main[0].id
}


# -------------------------------------------------------------------------------------
#  If mirroring_deployment = true, create mirroring deployment.
# -------------------------------------------------------------------------------------

// Create mirroring endpoint group
resource "google_network_security_mirroring_endpoint_group" "main" {
  count                       = var.mirroring_deployment ? 1 : 0
  mirroring_endpoint_group_id = "${local.prefix}panw-epg"
  location                    = "global"
  mirroring_deployment_group  = var.producer_dg
}

// Create intercept endpoint association
resource "google_network_security_mirroring_endpoint_group_association" "main" {
  count                                   = var.mirroring_deployment ? 1 : 0
  mirroring_endpoint_group_association_id = "${local.prefix}panw-epg-assoc"
  location                                = "global"
  network                                 = google_compute_network.main.id
  mirroring_endpoint_group                = google_network_security_mirroring_endpoint_group.main[0].id
}


# -------------------------------------------------------------------------------------
# Create firewall policy and rules to intercept or mirror traffic for the consumer VPC.
# -------------------------------------------------------------------------------------

// Create the Custom Security Profile
resource "google_network_security_security_profile" "main" {
  name     = "${local.prefix}panw-sp"
  parent   = "organizations/${var.org_id}"
  location = "global"
  type     = var.mirroring_deployment ? "CUSTOM_MIRRORING" : "CUSTOM_INTERCEPT"

  dynamic "custom_intercept_profile" {
    for_each = var.mirroring_deployment ? [] : [1]
    content {
      intercept_endpoint_group = google_network_security_intercept_endpoint_group.main[0].id
    }
  }

  dynamic "custom_mirroring_profile" {
    for_each = var.mirroring_deployment ? [1] : []
    content {
      mirroring_endpoint_group = google_network_security_mirroring_endpoint_group.main[0].id
    }
  }
}

// Create the Security Profile Group
resource "google_network_security_security_profile_group" "main" {
  name                     = "${local.prefix}panw-spg"
  parent                   = "organizations/${var.org_id}"
  location                 = "global"
  custom_intercept_profile = var.mirroring_deployment ? null : google_network_security_security_profile.main.id
  custom_mirroring_profile = var.mirroring_deployment ? google_network_security_security_profile.main.id : null
}

// Create the Global Network Firewall Policy (Common to both deployments)
resource "google_compute_network_firewall_policy" "main" {
  name    = "${local.prefix}consumer-policy"
  project = var.project_id
}


# -------------------------------------------------------------------------------------
# PATH A: Intercept Rules (Created only if mirroring_deployment = false)
# -------------------------------------------------------------------------------------

// Create a firewall rule to intercept all ingress traffic for inspection.
resource "google_compute_network_firewall_policy_rule" "ingress" {
  count                  = var.mirroring_deployment ? 0 : 1
  project                = var.project_id
  priority               = 10
  direction              = "INGRESS"
  action                 = "apply_security_profile_group"
  firewall_policy        = google_compute_network_firewall_policy.main.name
  security_profile_group = google_network_security_security_profile_group.main.id

  match {
    src_ip_ranges  = ["0.0.0.0/0"]
    dest_ip_ranges = ["0.0.0.0/0"]
    layer4_configs {
      ip_protocol = "all"
    }
  }
}

// Create a firewall rule to intercept all egress traffic for inspection.
resource "google_compute_network_firewall_policy_rule" "egress" {
  count                  = var.mirroring_deployment ? 0 : 1
  project                = var.project_id
  priority               = 11
  direction              = "EGRESS"
  action                 = "apply_security_profile_group"
  firewall_policy        = google_compute_network_firewall_policy.main.name
  security_profile_group = google_network_security_security_profile_group.main.id

  match {
    src_ip_ranges  = ["0.0.0.0/0"]
    dest_ip_ranges = ["0.0.0.0/0"]
    layer4_configs {
      ip_protocol = "all"
    }
  }
}


# -------------------------------------------------------------------------------------
# PATH B: Mirroring Rules (Created only if mirroring_deployment = true)
# -------------------------------------------------------------------------------------

// Create a mirroring rule for ingress traffic.
resource "google_compute_network_firewall_policy_packet_mirroring_rule" "ingress" {
  provider               = google-beta
  count                  = var.mirroring_deployment ? 1 : 0
  project                = var.project_id
  priority               = 10
  direction              = "INGRESS"
  action                 = "mirror"
  firewall_policy        = google_compute_network_firewall_policy.main.name
  security_profile_group = "//networksecurity.googleapis.com/${google_network_security_security_profile_group.main.id}"

  match {
    src_ip_ranges  = ["0.0.0.0/0"]
    dest_ip_ranges = ["0.0.0.0/0"]
    layer4_configs {
      ip_protocol = "all"
    }
  }
}

// Create a mirroring rule for egress traffic.
resource "google_compute_network_firewall_policy_packet_mirroring_rule" "egress" {
  provider               = google-beta
  count                  = var.mirroring_deployment ? 1 : 0
  project                = var.project_id
  priority               = 11
  direction              = "EGRESS"
  action                 = "mirror"
  firewall_policy        = google_compute_network_firewall_policy.main.name
  security_profile_group = "//networksecurity.googleapis.com/${google_network_security_security_profile_group.main.id}"

  match {
    src_ip_ranges  = ["0.0.0.0/0"]
    dest_ip_ranges = ["0.0.0.0/0"]
    layer4_configs {
      ip_protocol = "all"
    }
  }
}


# -------------------------------------------------------------------------------------
# Firewall Policy Association
# -------------------------------------------------------------------------------------

// Associate the firewall policy with the consumer VPC network (Common to both deployments)
resource "google_compute_network_firewall_policy_association" "main" {
  name              = "${local.prefix}consumer-policy-assoc"
  project           = var.project_id
  firewall_policy   = google_compute_network_firewall_policy.main.id
  attachment_target = google_compute_network.main.id
}