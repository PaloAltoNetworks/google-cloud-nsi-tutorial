output "COMPLETE" {
  value = <<EOF

    CONSUMER_PROJECT = ${var.project_id}
    CONSUMER_VPC     = ${google_compute_network.main.name}
    REGION           = ${var.region}
    ZONE             = ${google_compute_instance.client.zone}
    CLIENT_VM        = ${google_compute_instance.client.name}
    CLUSTER          = ${data.google_container_cluster.main.name}

EOF
}