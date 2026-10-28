output "frontend_url" {
  value = var.domain == "" ? google_cloud_run_v2_service.frontend.uri : "https://${var.domain}"
}

output "edge_ip" {
  description = "Point the domain's A record here (only with var.domain)."
  value       = var.domain == "" ? null : google_compute_global_address.web[0].address
}

output "api_url" {
  description = "Internal-only API URL (reachable from the VPC)."
  value       = google_cloud_run_v2_service.api.uri
}

output "image_repository" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}

output "migrate_job" {
  value = google_cloud_run_v2_job.migrate.name
}

output "data_bucket" {
  value = google_storage_bucket.data.name
}

output "backend_service_account" {
  value = google_service_account.backend.email
}
