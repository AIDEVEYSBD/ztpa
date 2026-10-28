variable "project_id" {
  description = "GCP project that hosts this deployment."
  type        = string
}

variable "region" {
  description = "Region for Cloud Run, Cloud SQL and the bucket."
  type        = string
  default     = "europe-west4"
}

variable "env" {
  description = "staging or prod. Both run with production rules (NPR_ENV)."
  type        = string
  validation {
    condition     = contains(["staging", "prod"], var.env)
    error_message = "env must be staging or prod."
  }
}

variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "frr"
}

# --- images: always by digest, never by tag -----------------------------------
variable "backend_image" {
  description = "Backend image by digest: REGION-docker.pkg.dev/PROJECT/REPO/backend@sha256:..."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.backend_image))
    error_message = "backend_image must be pinned by digest (@sha256:...)."
  }
}

variable "frontend_image" {
  description = "Frontend image by digest."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.frontend_image))
    error_message = "frontend_image must be pinned by digest (@sha256:...)."
  }
}

# --- identity ------------------------------------------------------------------
variable "app_url" {
  description = "Public URL users open, e.g. https://frr.example.com. Used for SSO callbacks and CORS."
  type        = string
}

variable "sso_issuer" {
  description = "OIDC issuer URL."
  type        = string
}

variable "sso_client_id" {
  description = "OIDC client id."
  type        = string
}

variable "sso_client_secret" {
  description = "OIDC client secret. Stored in Secret Manager."
  type        = string
  sensitive   = true
}

variable "sso_role_map" {
  description = "JSON mapping IdP app roles to product roles (see docs/SSO.md)."
  type        = string
  default     = ""
}

# --- AI ----------------------------------------------------------------------------
variable "vertex_location" {
  description = "Vertex AI location; 'global' has the widest model availability."
  type        = string
  default     = "global"
}

variable "vertex_model" {
  description = "Publisher-qualified Vertex model."
  type        = string
  default     = "google/gemini-2.5-pro"
}

variable "byok_secrets" {
  description = "Optional bring-your-own-key secrets for the backend, e.g. { OPENAI_API_KEY = \"...\" }. Each becomes a Secret Manager secret exposed as that env var."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "advisory_provider" {
  description = "ADVISORY_PROVIDER: auto prefers Vertex on GCP, then any BYOK key."
  type        = string
  default     = "auto"
}

# --- capacity ------------------------------------------------------------------
variable "db_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-custom-2-8192"
}

variable "db_high_availability" {
  description = "Regional (HA) Cloud SQL. Recommended for prod."
  type        = bool
  default     = true
}

variable "api_min_instances" {
  type    = number
  default = 1
}

variable "api_max_instances" {
  type    = number
  default = 10
}

variable "api_processes" {
  description = "uvicorn processes per API instance (WEB_CONCURRENCY). Keep cpu >= processes."
  type        = number
  default     = 2
}

variable "worker_min_instances" {
  description = "Workers poll the queue, so at least one must always run."
  type        = number
  default     = 1
  validation {
    condition     = var.worker_min_instances >= 1
    error_message = "At least one worker must run, or queued jobs never start."
  }
}

variable "worker_max_instances" {
  type    = number
  default = 4
}

variable "worker_concurrency" {
  description = "Job slots per worker instance."
  type        = number
  default     = 2
}

variable "frontend_min_instances" {
  type    = number
  default = 1
}

variable "frontend_max_instances" {
  type    = number
  default = 10
}

# --- edge (optional) -----------------------------------------------------------
variable "domain" {
  description = "If set, a global HTTPS load balancer with a managed certificate and Cloud Armor fronts the app on this domain, and the frontend accepts traffic only from it."
  type        = string
  default     = ""
}

variable "edge_rate_limit_per_minute" {
  description = "Cloud Armor per-client-IP request ceiling (only with a domain)."
  type        = number
  default     = 600
}

variable "frr_mode" {
  description = "Firewall Rule Review rules: no auto-approval and no device push anywhere (NPR_FRR_MODE)."
  type        = bool
  default     = true
}
