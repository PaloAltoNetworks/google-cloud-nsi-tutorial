variable "project_id" {
  description = "The deployment project ID."
  type        = string
}

variable "region" {
  description = "The region for the deployment."
  default     = "us-west1"
  type        = string
}

variable "mgmt_allow_ips" {
  description = "A list of IP addresses to be added to the consumer network's ingress firewall rule. The IP addresses will be able to access to the workloads in the consumer network."
  type        = list(string)
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

