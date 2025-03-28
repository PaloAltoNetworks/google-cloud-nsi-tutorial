# output "ENVIRONMENT_VARIABLES" {
#   value = format(
#     <<EOT

# export PRODUCER_PROJECT=%s
# export DATA_VPC=%s
# export BACKEND_SERVICE=%s
# export REGION=%s
# %s
# %s
# EOT
#     ,
#     var.project_id,
#     google_compute_network.data.name,
#     google_compute_region_backend_service.main.name,
#     var.region,
#     join("\n", [for i in range(length(sort(data.google_compute_zones.available.names))) : format("export ZONE%d=%s", i + 1, sort(data.google_compute_zones.available.names)[i])]),
#     join("\n", [for i in range(length(sort([for rule in google_compute_forwarding_rule.zone : rule.name]))) : "export FWD_RULE${i + 1}=${sort([for rule in google_compute_forwarding_rule.zone : rule.name])[i]}"])
#   )
# }



output "ENVIRONMENT_VARIABLES" {
  value = <<EOT

export PRODUCER_PROJECT=${var.project_id}
export DATA_VPC=${google_compute_network.data.name}
export DATA_SUBNET=${google_compute_subnetwork.data.name}
export REGION=${var.region}
export ZONE=${data.google_compute_zones.available.names[0]}
export BACKEND_SERVICE=${google_compute_region_backend_service.main.self_link}
EOT

}