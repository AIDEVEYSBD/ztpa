# Every secret lives in Secret Manager and reaches containers as an env var at
# start (value_source.secret_key_ref). Internal secrets are generated here; the
# SSO client secret and any BYOK keys are supplied by the operator.

resource "random_password" "internal" {
  for_each = toset(["auth", "proxy", "artifact"])
  length   = 48
  special  = false
}

locals {
  secrets = merge(
    {
      "database-url"       = local.database_url
      "database-admin-url" = local.database_admin_url
      "app-db-password"    = random_password.db_app.result
      "auth-secret"        = random_password.internal["auth"].result
      "proxy-secret"       = random_password.internal["proxy"].result
      "artifact-key"       = random_password.internal["artifact"].result
      "sso-client-secret"  = var.sso_client_secret
    },
    { for k, v in nonsensitive(var.byok_secrets) : "byok-${lower(replace(k, "_", "-"))}" => v },
    var.breakglass_email == "" ? {} : { "breakglass-password-hash" = var.breakglass_password_hash }
  )
  byok_env = { for k in keys(nonsensitive(var.byok_secrets)) : k => "byok-${lower(replace(k, "_", "-"))}" }
}

resource "google_secret_manager_secret" "s" {
  for_each  = nonsensitive(toset(keys(local.secrets)))
  secret_id = "${local.n}-${each.value}"
  labels    = local.labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "s" {
  for_each    = nonsensitive(toset(keys(local.secrets)))
  secret      = google_secret_manager_secret.s[each.value].id
  secret_data = local.secrets[each.value]
}
