# -------------------------------------------------------------------------------------
# Provider configuration
# -------------------------------------------------------------------------------------

terraform {
  required_version = "> 1.5, < 2.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">=4.64, < 6.18"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">=4.64, < 6.18"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  default_labels = {
    panw = "true"
  }
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
  default_labels = {
    panw = "true"
  }
}

# -------------------------------------------------------------------------------------
# Localized variables
# -------------------------------------------------------------------------------------

locals {
  prefix    = var.prefix != null && var.prefix != "" ? "${var.prefix}-" : ""
  image_url = "https://www.googleapis.com/compute/v1/projects/paloaltonetworksgcp-public/global/images/${var.image_name}"
}



# -------------------------------------------------------------------------------------
# Create management and dataplane VPCs, subnets, and firewall rules.
# -------------------------------------------------------------------------------------

// Create management VPC
resource "google_compute_network" "mgmt" {
  name                    = "${local.prefix}mgmt"
  auto_create_subnetworks = false
}

// Create dataplane VPC
resource "google_compute_network" "data" {
  name                    = "${local.prefix}data"
  auto_create_subnetworks = false
}

// Create management subnet
resource "google_compute_subnetwork" "mgmt" {
  name          = "${local.prefix}${var.region}-mgmt"
  ip_cidr_range = var.subnet_cidr_mgmt
  region        = var.region
  network       = google_compute_network.mgmt.id
}

// Create dataplane subnet
resource "google_compute_subnetwork" "data" {
  name          = "${local.prefix}${var.region}-data"
  ip_cidr_range = var.subnet_cidr_data
  region        = var.region
  network       = google_compute_network.data.id
}

// Firewall rule to allow management access
resource "google_compute_firewall" "mgmt" {
  name          = "${local.prefix}mgmt"
  network       = google_compute_network.mgmt.name
  source_ranges = var.mgmt_allow_ips

  allow {
    protocol = "tcp"
    ports    = ["443", "22", "3978"]
  }
}

// Allow all traffic to firewall's dataplane VPC
resource "google_compute_firewall" "data" {
  name          = "${local.prefix}data"
  network       = google_compute_network.data.name
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "all"
    ports    = []
  }
}
# -------------------------------------------------------------------------------------
#  Create internal load balancer.
# -------------------------------------------------------------------------------------

resource "google_compute_region_health_check" "main" {
  name = "${local.prefix}panw-hc"
  http_health_check {
    port         = 80
    request_path = "/unauth/php/health.php"
  }
}

resource "google_compute_region_backend_service" "main" {
  name          = "${local.prefix}panw-lb"
  protocol      = "UDP"
  network       = google_compute_network.data.id
  health_checks = [google_compute_region_health_check.main.self_link]

  backend {
    group          = google_compute_region_instance_group_manager.main.instance_group
    balancing_mode = "CONNECTION"
  }
}



# -------------------------------------------------------------------------------------
#  Create a mirroring deployment group with mirroring deployments and forwarding rules 
#  for every zone in var.region.
# -------------------------------------------------------------------------------------

resource "google_network_security_mirroring_deployment_group" "main" {
  provider                      = google-beta
  mirroring_deployment_group_id = "${local.prefix}panw-mdg"
  location                      = "global"
  network                       = google_compute_network.data.id
}

data "google_compute_zones" "available" {
  region = var.region
}

resource "google_compute_forwarding_rule" "zone" {
  for_each               = toset(data.google_compute_zones.available.names)
  name                   = "${local.prefix}panw-lb-rule-${each.key}"
  subnetwork             = google_compute_subnetwork.data.id
  backend_service        = google_compute_region_backend_service.main.self_link
  load_balancing_scheme  = "INTERNAL"
  ip_protocol            = "UDP"
  ports                  = [6081]
  is_mirroring_collector = true
}

resource "google_network_security_mirroring_deployment" "zone" {
  for_each = toset(data.google_compute_zones.available.names)
  provider                   = google-beta
  mirroring_deployment_id    = "${local.prefix}panw-md-${each.key}"
  location                   = each.value
  forwarding_rule            = google_compute_forwarding_rule.zone[each.key].id
  mirroring_deployment_group = google_network_security_mirroring_deployment_group.main.id
}



# -------------------------------------------------------------------------------------
#  Create firewall service account, instance template, MIG, and autoscaler.
# -------------------------------------------------------------------------------------

resource "google_service_account" "main" {
  account_id = "${local.prefix}panw-sa"
}

resource "google_project_iam_member" "main" {
  for_each = var.roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.main.email}"
}

resource "google_compute_instance_template" "main" {
  name_prefix      = "${local.prefix}panw-template"
  machine_type     = var.machine_type
  min_cpu_platform = "Intel Cascade Lake"
  tags             = ["panw-tutorial"]
  can_ip_forward   = true

  metadata = {
    type                                  = "dhcp-client"
    dhcp-send-client-id                   = "yes"
    dhcp-accept-server-hostname           = "yes"
    dhcp-accept-server-domain             = "yes"
    vm-series-auto-registration-pin-id    = var.csp_pin_id
    vm-series-auto-registration-pin-value = var.csp_pin_value
    authcodes                             = var.csp_authcodes
    dns-primary                           = "169.254.169.254"
    vmseries-bootstrap-gce-storagebucket  = module.bootstrap.bucket_name
  }

  network_interface {
    subnetwork = google_compute_subnetwork.mgmt.id
    access_config {}
  }

  network_interface {
    subnetwork = google_compute_subnetwork.data.id
    
  }

  disk {
    source_image = local.image_url
    disk_type    = "pd-ssd"
    auto_delete  = true
    boot         = true
  }

  lifecycle {
    create_before_destroy = true
  }

  service_account {
    email = google_service_account.main.email
    scopes = [
      "https://www.googleapis.com/auth/compute.readonly",
      "https://www.googleapis.com/auth/cloud.useraccounts.readonly",
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
    ]
  }
}


resource "google_compute_region_instance_group_manager" "main" {
  name                      = "${local.prefix}panw-mig"
  base_instance_name        = "${local.prefix}panw-firewall"
  distribution_policy_zones = data.google_compute_zones.available.names

  version {
    instance_template = google_compute_instance_template.main.id
  }
}


resource "google_compute_region_autoscaler" "main" {
  name   = "${local.prefix}panw-autoscaler"
  target = google_compute_region_instance_group_manager.main.id

  autoscaling_policy {
    min_replicas    = var.max_firewalls
    max_replicas    = var.min_firewalls
    cooldown_period = 480
  }
}





module "iam_service_account" {
  source             = "PaloAltoNetworks/swfw-modules/google//modules/iam_service_account"
  version            = "~> 2.0"
  service_account_id = "${local.prefix}vmseries-mig-sa"
  project_id         = var.project_id
}


// Create the GCS bootstrap bucket with local firewall config (bootstrap.xml).
module "bootstrap" {
  source          = "PaloAltoNetworks/swfw-modules/google//modules/bootstrap"
  version         = "~> 2.0"
  service_account = module.iam_service_account.email
  location        = "US"

  // If panorama_ip is provided, skip uploading the local firewall config (bootstrap.xml) to GCS bootstrap bucket.
  files = {
    "bootstrap_files/bootstrap.xml" = "config/bootstrap.xml"
    "bootstrap_files/init-cfg.txt"  = "config/init-cfg.txt"
    "bootstrap_files/authcodes"     = "license/authcodes"
  }
}