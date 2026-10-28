# One service account per role, least privilege. No keys are created: Cloud Run
# runs each service as its account and every client uses ADC.

resource "google_service_account" "backend" {
  account_id   = "${local.n}-backend"
  display_name = "FRR backend (API, worker)"
}

resource "google_service_account" "migrate" {
  account_id   = "${local.n}-migrate"
  display_name = "FRR schema migrations (the only DB-owner identity)"
}

resource "google_secret_manager_secret_iam_member" "migrate" {
  for_each  = toset(["database-admin-url", "app-db-password"])
  secret_id = google_secret_manager_secret.s[each.value].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.migrate.email}"
}

resource "google_project_iam_member" "migrate_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.migrate.email}"
}

resource "google_service_account" "frontend" {
  account_id   = "${local.n}-frontend"
  display_name = "FRR frontend"
}

locals {
  backend_secrets  = concat(["database-url", "proxy-secret", "artifact-key"], values(local.byok_env))
  frontend_secrets = ["database-url", "auth-secret", "proxy-secret", "sso-client-secret"]
  backend_roles = [
    "roles/aiplatform.user",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/cloudtrace.agent",
  ]
}

resource "google_secret_manager_secret_iam_member" "backend" {
  for_each  = toset(local.backend_secrets)
  secret_id = google_secret_manager_secret.s[each.value].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.backend.email}"
}

resource "google_secret_manager_secret_iam_member" "frontend" {
  for_each  = toset(local.frontend_secrets)
  secret_id = google_secret_manager_secret.s[each.value].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.frontend.email}"
}

resource "google_project_iam_member" "backend" {
  for_each = toset(local.backend_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.backend.email}"
}

resource "google_project_iam_member" "frontend_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.frontend.email}"
}

resource "google_storage_bucket_iam_member" "backend_data" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.backend.email}"
}
