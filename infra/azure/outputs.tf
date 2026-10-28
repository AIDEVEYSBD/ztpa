output "frontend_url" {
  value = "https://${azurerm_container_app.frontend.ingress[0].fqdn}"
}

output "api_internal_fqdn" {
  value = azurerm_container_app.api.ingress[0].fqdn
}

output "registry" {
  value = azurerm_container_registry.acr.login_server
}

output "resource_group" {
  value = azurerm_resource_group.rg.name
}

output "migrate_job" {
  value = azurerm_container_app_job.migrate.name
}

output "key_vault" {
  value = azurerm_key_vault.kv.name
}

output "storage_account" {
  value = azurerm_storage_account.data.name
}
