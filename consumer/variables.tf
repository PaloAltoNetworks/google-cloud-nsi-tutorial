variable "org_id" {
  description = "The GCP organization ID."
  type        = string
}

variable "project_id" {
  description = "The deployment project ID."
  type        = string
}

variable "billing_project_id" {
  description = "The billing project ID."
  type        = string
}

variable "producer_dg" {
  description = "The produce's intercept deployment group"
  type        = string
}

variable "mgmt_allow_ips" {
  description = "A list of IP addresses to be added to the consumer network's ingress firewall rule. The IP addresses will be able to access to the workloads in the consumer network."
  type        = list(string)
}

variable "region" {
  description = "The region for the deployment."
  type        = string
}

variable "mirroring_deployment" {
  description = "If true, a mirroring deployment will be created.  If false, an intercept deployment will be created."
  type        = bool
  default     = false
}

variable "prefix" {
  description = "A unique string to prepend to each created resource."
  type        = string
  default     = ""
}

variable "subnet_cidr" {
  description = "The IPv4 subnet CIDR for the consumer subnetwork."
  default     = "10.1.0.0/24"
  type        = string
}