output "SET_ENV_VARS" {
  value = <<EOF

export PROJECT_ID=${var.project_id}
export CONSUMER_VPC=${google_compute_network.main.name}
export REGION=${var.region}
export CLUSTER=${data.google_container_cluster.main.name}

EOF
}