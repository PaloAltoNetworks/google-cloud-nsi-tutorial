variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
}

variable "public_key_path" {
  description = "Local path to public SSH key. To generate the key pair use `ssh-keygen -t rsa -C admin -N '' -f id_rsa`  If you do not have a public key, run `ssh-keygen -f ~/.ssh/demo-key -t rsa -C admin`"
  type        = string
  default     = null
}

variable "mgmt_allow_ips" {
  description = "A list of IP addresses to be added to the management network's ingress firewall rule. The IP addresses will be able to access to the VM-Series management interface."
  type        = list(string)
}

variable "mgmt_public_ip" {
  description = "If true, a public IP will be set on the management interface."
  type        = bool
  default     = false
}

variable "prefix" {
  description = "An optional name to prepend to each created resource."
  default     = null
  type        = string
}

variable "subnet_cidr_mgmt" {
  description = "The IPv4 CIDR for the management subnet."
  default     = "10.0.0.0/28"
  type        = string
}

variable "subnet_cidr_data" {
  description = "The IPv4 CIDR for the dataplane subnet."
  default     = "10.0.1.0/28"
  type        = string
}

variable "image_name" {
  description = "Name of the firewall image within the paloaltonetworksgcp-public project. To list available images, run: `gcloud compute images list --project paloaltonetworksgcp-public --no-standard-images`. If you are using a custom image in a different project, update `local.firewall_image_url` in `main.tf` to match your URL."
  default     = "vmseries-flex-bundle2-1126"
  type        = string
}

variable "machine_type" {
  description = "The machine type for the firewalls (n2 or e2 recommended)."
  default     = "n2-standard-4"
  type        = string
}

variable "max_firewalls" {
  description = "The maximum number of firewalls to scale up to during scaling event."
  default     = 1
}

variable "min_firewalls" {
  description = "The minimum number of firewalls to scale down to (should always be more than 1)."
  default     = 1
}

variable "csp_authcodes" {
  description = "(BYOL only) An authcode that is registered with your CSP account. "
  default     = ""
  type        = string
}

variable "csp_pin_id" {
  description = "The firewall registration PIN ID for installing the device certificate onto the firewall."
  default     = ""
  type        = string
}

variable "csp_pin_value" {
  description = "The firewall registration PIN Value for installing the device certificate onto the firewall."
  default     = ""
  type        = string
}

variable "roles" {
  description = "Roles to assign to the firewall's service account."
  default = [
    "roles/compute.networkViewer",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/viewer",
    "roles/stackdriver.accounts.viewer",
    "roles/stackdriver.resourceMetadata.writer",
  ]
  type = set(string)
}

variable "metadata" {
  description = "Metadata for VM-Series firewall. The metadata is used to perform mgmt-interface-swap and for bootstrapping the VM-Series."
  type        = map(string)
  default     = {}
}
