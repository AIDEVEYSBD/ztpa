data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 5
  special = false
  upper   = false
}

locals {
  n    = "${var.name_prefix}-${var.env}"
  flat = "${var.name_prefix}${var.env}${random_string.suffix.result}" # for names without dashes
  tags = { app = var.name_prefix, env = var.env, managed-by = "terraform" }
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-${local.n}"
  location = var.location
  tags     = local.tags
}

# --- network ------------------------------------------------------------------
resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-${local.n}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  address_space       = ["10.30.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "aca" {
  name                 = "snet-aca"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.30.0.0/23"]
  delegation {
    name = "aca"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "pg" {
  name                 = "snet-pg"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.30.2.0/24"]
  delegation {
    name = "pg"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "pe" {
  name                 = "snet-pe"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.30.3.0/24"]
}

resource "azurerm_private_dns_zone" "z" {
  for_each = {
    pg    = "${local.n}.private.postgres.database.azure.com"
    blob  = "privatelink.blob.core.windows.net"
    vault = "privatelink.vaultcore.azure.net"
  }
  name                = each.value
  resource_group_name = azurerm_resource_group.rg.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "z" {
  for_each              = azurerm_private_dns_zone.z
  name                  = "link-${each.key}"
  resource_group_name   = azurerm_resource_group.rg.name
  private_dns_zone_name = each.value.name
  virtual_network_id    = azurerm_virtual_network.vnet.id
}

# --- observability ----------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "logs" {
  name                = "log-${local.n}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = local.tags
}

resource "azurerm_application_insights" "ai" {
  name                = "appi-${local.n}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  workspace_id        = azurerm_log_analytics_workspace.logs.id
  application_type    = "web"
  tags                = local.tags
}

# --- registry -----------------------------------------------------------------------
resource "azurerm_container_registry" "acr" {
  name                = "acr${local.flat}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  sku                 = "Standard"
  admin_enabled       = false # pulls use managed identity; pushes use CI's federated identity
  tags                = local.tags
}

# --- identities ------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "id" {
  for_each            = toset(["backend", "frontend", "migrate"])
  name                = "id-${local.n}-${each.value}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  tags                = local.tags
}
