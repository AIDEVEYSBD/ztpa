variable "subscription_id" {
  type = string
}

variable "location" {
  type    = string
  default = "westeurope"
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
  type    = string
  default = "frr"
}

variable "operator_ip_cidrs" {
  description = "Public CIDRs allowed to reach Key Vault's data plane (the machine or CI runner applying Terraform). Everything else uses private endpoints."
  type        = list(string)
}

# --- images: by digest only ---------------------------------------------------
variable "backend_image" {
  description = "<acr>.azurecr.io/backend@sha256:..."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.backend_image))
    error_message = "backend_image must be pinned by digest (@sha256:...)."
  }
}

variable "frontend_image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.frontend_image))
    error_message = "frontend_image must be pinned by digest (@sha256:...)."
  }
}

# --- identity -------------------------------------------------------------------
variable "app_url" {
  description = "Public URL users open (SSO callbacks, CORS)."
  type        = string
}

variable "sso_issuer" {
  type = string
}

variable "sso_client_id" {
  type = string
}

variable "sso_client_secret" {
  type      = string
  sensitive = true
}

variable "sso_role_map" {
  type    = string
  default = ""
}

# --- AI: the subscription's own Azure AI Foundry deployment ----------------------
variable "azure_ai_endpoint" {
  description = "https://<account>.cognitiveservices.azure.com/ ; empty to rely on BYOK only."
  type        = string
  default     = ""
}

variable "azure_ai_deployment" {
  type    = string
  default = ""
}

variable "azure_ai_account_id" {
  description = "Resource id of the AI Services account; the backend identity is granted 'Cognitive Services OpenAI User' on it."
  type        = string
  default     = ""
}

variable "advisory_provider" {
  type    = string
  default = "auto"
}

variable "byok_secrets" {
  description = "Optional BYOK secrets for the backend, e.g. { OPENAI_API_KEY = \"...\" }."
  type        = map(string)
  default     = {}
  sensitive   = true
}

# --- capacity --------------------------------------------------------------------
variable "db_sku" {
  type    = string
  default = "GP_Standard_D2ds_v5"
}

variable "db_storage_mb" {
  type    = number
  default = 131072
}

variable "db_high_availability" {
  type    = bool
  default = true
}

variable "api_min_replicas" {
  type    = number
  default = 1
}

variable "api_max_replicas" {
  type    = number
  default = 10
}

variable "api_processes" {
  type    = number
  default = 2
}

variable "worker_max_replicas" {
  type    = number
  default = 4
}

variable "worker_concurrency" {
  type    = number
  default = 2
}

variable "worker_jobs_per_replica" {
  description = "KEDA target: ready jobs per worker replica before scaling out."
  type        = number
  default     = 5
}

variable "frontend_min_replicas" {
  type    = number
  default = 1
}

variable "frontend_max_replicas" {
  type    = number
  default = 10
}

variable "alert_emails" {
  type    = list(string)
  default = []
}

variable "frr_mode" {
  description = "Firewall Rule Review rules: no auto-approval and no device push anywhere (NPR_FRR_MODE)."
  type        = bool
  default     = true
}

variable "breakglass_email" {
  description = "Arms the break-glass password login (docs/BREAKGLASS.md). Empty = off. Staging without an IdP, or recovery; never leave it set in prod."
  type        = string
  default     = ""
}

variable "breakglass_password_hash" {
  description = "bcrypt hash of the break-glass password (stored in Key Vault)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "db_storage_tier" {
  description = "Premium SSD performance tier for the database disk; must suit db_storage_mb (P4 for 32 GiB ... P30 for 1 TiB)."
  type        = string
  default     = "P30"
}
