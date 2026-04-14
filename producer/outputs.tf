output "DEPLOYMENT_GROUP" {
  description = "The ID of the producer deployment group (either Intercept or Mirroring)."
  value = try(
    google_network_security_intercept_deployment_group.main[0].id,
    google_network_security_mirroring_deployment_group.main[0].id,
    null
  )
}