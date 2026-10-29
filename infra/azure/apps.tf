resource "azurerm_container_app_environment" "env" {
  name                       = "cae-${local.n}"
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = var.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id
  infrastructure_subnet_id   = azurerm_subnet.aca.id
  zone_redundancy_enabled    = var.env == "prod"
  tags                       = local.tags

  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }
}

locals {
  backend_id  = azurerm_user_assigned_identity.id["backend"]
  frontend_id = azurerm_user_assigned_identity.id["frontend"]
  migrate_id  = azurerm_user_assigned_identity.id["migrate"]

  backend_env = {
    NPR_ENV                               = var.env
    NPR_FRR_MODE                          = tostring(var.frr_mode)
    NPR_PLATFORM                          = "azure"
    NPR_JOBS_INLINE                       = "false"
    NPR_STORAGE_URL                       = "az://${azurerm_storage_account.data.name}/${azurerm_storage_container.data.name}/frr"
    FRONTEND_ORIGIN                       = var.app_url
    ADVISORY_PROVIDER                     = var.advisory_provider
    AZURE_AI_ENDPOINT                     = var.azure_ai_endpoint
    AZURE_AI_DEPLOYMENT                   = var.azure_ai_deployment
    AZURE_AI_AUTH_MODE                    = "identity"
    AZURE_AI_CLIENT_ID                    = local.backend_id.client_id
    AZURE_CLIENT_ID                       = local.backend_id.client_id # DefaultAzureCredential (Blob)
    APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.ai.connection_string
    DB_POOL_MAX                           = "8"
  }
  backend_secret_env = merge({
    DATABASE_URL     = "database-url"
    NPR_PROXY_SECRET = "proxy-secret"
    NPR_ARTIFACT_KEY = "artifact-key"
  }, local.byok_env)
}

# --- API: internal ingress only --------------------------------------------------
resource "azurerm_container_app" "api" {
  name                         = "ca-${local.n}-api"
  resource_group_name          = azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [local.backend_id.id]
  }

  registry {
    server   = azurerm_container_registry.acr.login_server
    identity = local.backend_id.id
  }

  dynamic "secret" {
    for_each = toset(values(local.backend_secret_env))
    content {
      name                = secret.value
      key_vault_secret_id = azurerm_key_vault_secret.s[secret.value].versionless_id
      identity            = local.backend_id.id
    }
  }

  ingress {
    external_enabled = false
    target_port      = 8000
    transport        = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.api_min_replicas
    max_replicas = var.api_max_replicas

    http_scale_rule {
      name                = "concurrency"
      concurrent_requests = "40"
    }

    container {
      name   = "api"
      image  = var.backend_image
      cpu    = 2
      memory = "4Gi"

      env {
        name  = "WEB_CONCURRENCY"
        value = tostring(var.api_processes)
      }
      dynamic "env" {
        for_each = local.backend_env
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.backend_secret_env
        content {
          name        = env.key
          secret_name = env.value
        }
      }

      startup_probe {
        transport               = "HTTP"
        port                    = 8000
        path                    = "/api/live"
        interval_seconds        = 3
        failure_count_threshold = 20
      }
      liveness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/api/live"
      }
      readiness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/api/live"
      }
    }
  }

  depends_on = [time_sleep.rbac]
}

# --- worker: no ingress; scales on queue depth (KEDA PostgreSQL scaler) -------------
resource "azurerm_container_app" "worker" {
  name                         = "ca-${local.n}-worker"
  resource_group_name          = azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [local.backend_id.id]
  }

  registry {
    server   = azurerm_container_registry.acr.login_server
    identity = local.backend_id.id
  }

  dynamic "secret" {
    for_each = toset(values(local.backend_secret_env))
    content {
      name                = secret.value
      key_vault_secret_id = azurerm_key_vault_secret.s[secret.value].versionless_id
      identity            = local.backend_id.id
    }
  }

  template {
    min_replicas = 1 # one always polling, so a job never waits on a scale-from-zero
    max_replicas = var.worker_max_replicas

    custom_scale_rule {
      name             = "queue-depth"
      custom_rule_type = "postgresql"
      metadata = {
        query            = "SELECT count(*) FROM ztpa.jobs WHERE status = 'queued' AND run_after <= now()"
        targetQueryValue = tostring(var.worker_jobs_per_replica)
      }
      authentication {
        secret_name       = "database-url"
        trigger_parameter = "connection"
      }
    }

    container {
      name    = "worker"
      image   = var.backend_image
      cpu     = 2
      memory  = "4Gi"
      command = ["python", "-m", "src.jobs.worker"]
      args    = ["--concurrency", tostring(var.worker_concurrency), "--health-port", "8080"]

      dynamic "env" {
        for_each = local.backend_env
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.backend_secret_env
        content {
          name        = env.key
          secret_name = env.value
        }
      }

      liveness_probe {
        transport = "HTTP"
        port      = 8080
        path      = "/"
      }
    }
  }

  depends_on = [time_sleep.rbac]
}

# --- migrate: manual job, triggered by CI before each rollout ------------------------
resource "azurerm_container_app_job" "migrate" {
  name                         = "caj-${local.n}-migrate"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = var.location
  container_app_environment_id = azurerm_container_app_environment.env.id
  workload_profile_name        = "Consumption"
  replica_timeout_in_seconds   = 900
  replica_retry_limit          = 1
  tags                         = local.tags

  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [local.migrate_id.id]
  }

  registry {
    server   = azurerm_container_registry.acr.login_server
    identity = local.migrate_id.id
  }

  dynamic "secret" {
    for_each = toset(["database-admin-url", "app-db-password"])
    content {
      name                = secret.value
      key_vault_secret_id = azurerm_key_vault_secret.s[secret.value].versionless_id
      identity            = local.migrate_id.id
    }
  }

  template {
    container {
      name    = "migrate"
      image   = var.backend_image
      cpu     = 0.5
      memory  = "1Gi"
      command = ["python", "/app/db/migrate.py", "--bootstrap", "--ensure-app-role"]
      env {
        name        = "DATABASE_URL"
        secret_name = "database-admin-url"
      }
      env {
        name        = "NPR_APP_DB_PASSWORD"
        secret_name = "app-db-password"
      }
    }
  }

  depends_on = [time_sleep.rbac]
}

# --- frontend: the one public entry -----------------------------------------------------
resource "azurerm_container_app" "frontend" {
  name                         = "ca-${local.n}-web"
  resource_group_name          = azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [local.frontend_id.id]
  }

  registry {
    server   = azurerm_container_registry.acr.login_server
    identity = local.frontend_id.id
  }

  dynamic "secret" {
    for_each = toset(concat(["auth-secret", "proxy-secret", "database-url", "sso-client-secret"],
    var.breakglass_email == "" ? [] : ["breakglass-password-hash"]))
    content {
      name                = secret.value
      key_vault_secret_id = azurerm_key_vault_secret.s[secret.value].versionless_id
      identity            = local.frontend_id.id
    }
  }

  ingress {
    external_enabled = true
    target_port      = 3000
    transport        = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.frontend_min_replicas
    max_replicas = var.frontend_max_replicas

    http_scale_rule {
      name                = "concurrency"
      concurrent_requests = "80"
    }

    container {
      name   = "web"
      image  = var.frontend_image
      cpu    = 1
      memory = "2Gi"

      dynamic "env" {
        for_each = merge({
          BACKEND_URL     = "https://${azurerm_container_app.api.ingress[0].fqdn}"
          AUTH_URL        = var.app_url
          APP_URL         = var.app_url
          AUTH_TRUST_HOST = "true"
          SSO_ISSUER      = var.sso_issuer
          SSO_CLIENT_ID   = var.sso_client_id
          SSO_ROLE_MAP    = var.sso_role_map
          # Only Front Door's own requests are served when it is in front (frontend/middleware.ts).
          NPR_EDGE_ID = var.domain == "" ? "" : azurerm_cdn_frontdoor_profile.fd[0].resource_guid
          }, var.breakglass_email == "" ? {} : {
          AUTH_LOCAL_LOGIN           = "true"
          BREAKGLASS_EMAIL           = var.breakglass_email
          BREAKGLASS_SESSION_MAX_AGE = "3600"
        })
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = merge({
          AUTH_SECRET       = "auth-secret"
          NPR_PROXY_SECRET  = "proxy-secret"
          DATABASE_URL      = "database-url"
          SSO_CLIENT_SECRET = "sso-client-secret"
        }, var.breakglass_email == "" ? {} : { BREAKGLASS_PASSWORD_HASH = "breakglass-password-hash" })
        content {
          name        = env.key
          secret_name = env.value
        }
      }

      startup_probe {
        transport               = "TCP"
        port                    = 3000
        interval_seconds        = 3
        failure_count_threshold = 20
      }
    }
  }

  depends_on = [time_sleep.rbac]
}
