locals {
  n      = "${var.name_prefix}-${var.env}"
  labels = { app = var.name_prefix, env = var.env, managed-by = "terraform" }

  apis = [
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "servicenetworking.googleapis.com",
    "secretmanager.googleapis.com",
    "aiplatform.googleapis.com",
    "artifactregistry.googleapis.com",
    "compute.googleapis.com",
    "cloudtrace.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each           = toset(local.apis)
  service            = each.value
  disable_on_destroy = false
}

# --- container registry -------------------------------------------------------
resource "google_artifact_registry_repository" "images" {
  repository_id = local.n
  location      = var.region
  format        = "DOCKER"
  labels        = local.labels

  # Untagged images (superseded builds) are cleaned up; anything a revision
  # still references by digest keeps its tag from CI.
  cleanup_policies {
    id     = "drop-untagged"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "2592000s"
    }
  }
  depends_on = [google_project_service.apis]
}

# --- object storage: uploaded exports and snapshot artifacts -----------------
resource "google_storage_bucket" "data" {
  name                        = "${var.project_id}-${local.n}-data"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = local.labels

  versioning { enabled = true }

  lifecycle_rule {
    condition {
      num_newer_versions = 3
      with_state         = "ARCHIVED"
    }
    action { type = "Delete" }
  }
  lifecycle_rule {
    condition {
      days_since_noncurrent_time = 30
    }
    action { type = "Delete" }
  }
}
