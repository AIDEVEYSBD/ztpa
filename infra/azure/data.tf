# --- PostgreSQL: private access only -----------------------------------------
resource "random_password" "db" {
  for_each = toset(["admin", "app"])
  length   = 40
  special  = false
}

resource "azurerm_postgresql_flexible_server" "pg" {
  name                          = "psql-${local.n}-${random_string.suffix.result}"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = var.location
  version                       = "16"
  sku_name                      = var.db_sku
  storage_mb                    = var.db_storage_mb
  storage_tier                  = var.db_storage_tier
  auto_grow_enabled             = true
  delegated_subnet_id           = azurerm_subnet.pg.id
  private_dns_zone_id           = azurerm_private_dns_zone.z["pg"].id
  public_network_access_enabled = false
  administrator_login           = "npr_admin"
  administrator_password        = random_password.db["admin"].result
  backup_retention_days         = 14
  geo_redundant_backup_enabled  = var.env == "prod"
  zone                          = "1"
  tags                          = local.tags

  dynamic "high_availability" {
    for_each = var.db_high_availability ? [1] : []
    content {
      mode                      = "ZoneRedundant"
      standby_availability_zone = "2"
    }
  }

  maintenance_window {
    day_of_week  = 0
    start_hour   = 3
    start_minute = 0
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.z]

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [zone, high_availability[0].standby_availability_zone]
  }
}

resource "azurerm_postgresql_flexible_server_database" "app" {
  name      = "npr"
  server_id = azurerm_postgresql_flexible_server.pg.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

# pgvector for retrieval (RAG over standards and runbooks).
resource "azurerm_postgresql_flexible_server_configuration" "extensions" {
  name      = "azure.extensions"
  server_id = azurerm_postgresql_flexible_server.pg.id
  value     = "VECTOR"
}

locals {
  db_host            = azurerm_postgresql_flexible_server.pg.fqdn
  database_url       = "postgresql://npr_app:${random_password.db["app"].result}@${local.db_host}:5432/npr?sslmode=require"
  database_admin_url = "postgresql://npr_admin:${random_password.db["admin"].result}@${local.db_host}:5432/npr?sslmode=require"
}

# --- Blob storage: AAD only, private endpoint only -------------------------------
resource "azurerm_storage_account" "data" {
  name                            = "st${local.flat}"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = var.env == "prod" ? "ZRS" : "LRS"
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false
  default_to_oauth_authentication = true
  tags                            = local.tags

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 14
    }
    container_delete_retention_policy {
      days = 14
    }
  }
}

resource "azurerm_storage_container" "data" {
  name                  = "data"
  storage_account_id    = azurerm_storage_account.data.id
  container_access_type = "private"
}

resource "azurerm_private_endpoint" "blob" {
  name                = "pe-${local.n}-blob"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  subnet_id           = azurerm_subnet.pe.id
  tags                = local.tags
  private_service_connection {
    name                           = "blob"
    private_connection_resource_id = azurerm_storage_account.data.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.z["blob"].id]
  }
}

# --- Key Vault: RBAC, purge protection, private endpoint ---------------------------
resource "azurerm_key_vault" "kv" {
  name                       = "kv-${local.flat}"
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = var.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  purge_protection_enabled   = true
  soft_delete_retention_days = 30
  tags                       = local.tags

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.operator_ip_cidrs
  }
}

resource "azurerm_private_endpoint" "vault" {
  name                = "pe-${local.n}-kv"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  subnet_id           = azurerm_subnet.pe.id
  tags                = local.tags
  private_service_connection {
    name                           = "vault"
    private_connection_resource_id = azurerm_key_vault.kv.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "vault"
    private_dns_zone_ids = [azurerm_private_dns_zone.z["vault"].id]
  }
}

# The identity applying Terraform writes the secret values.
resource "azurerm_role_assignment" "kv_operator" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

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
      "app-db-password"    = random_password.db["app"].result
      "auth-secret"        = random_password.internal["auth"].result
      "proxy-secret"       = random_password.internal["proxy"].result
      "artifact-key"       = random_password.internal["artifact"].result
      "sso-client-secret"  = var.sso_client_secret
    },
    { for k, v in nonsensitive(var.byok_secrets) : "byok-${lower(replace(k, "_", "-"))}" => v },
    var.breakglass_email == "" ? {} : { "breakglass-password-hash" = var.breakglass_password_hash },
    nonsensitive(var.proxy_secret_previous) == "" ? {} : { "proxy-secret-previous" = var.proxy_secret_previous }
  )
  byok_env = { for k in keys(nonsensitive(var.byok_secrets)) : k => "byok-${lower(replace(k, "_", "-"))}" }
}

# RBAC assignments take time to reach the data plane.
resource "time_sleep" "kv_rbac" {
  depends_on      = [azurerm_role_assignment.kv_operator]
  create_duration = "60s"
}

resource "azurerm_key_vault_secret" "s" {
  for_each     = nonsensitive(toset(keys(local.secrets)))
  name         = each.value
  value        = local.secrets[each.value]
  key_vault_id = azurerm_key_vault.kv.id
  content_type = "text/plain"
  depends_on   = [time_sleep.kv_rbac]
}
