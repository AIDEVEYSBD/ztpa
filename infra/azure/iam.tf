locals {
  ids = { for k, v in azurerm_user_assigned_identity.id : k => v.principal_id }

  role_assignments = merge(
    { for who in ["backend", "frontend", "migrate"] : "acr-${who}" => {
    scope = azurerm_container_registry.acr.id, role = "AcrPull", who = who } },
    { for who in ["backend", "frontend", "migrate"] : "kv-${who}" => {
    scope = azurerm_key_vault.kv.id, role = "Key Vault Secrets User", who = who } },
    { "blob-backend" = {
    scope = azurerm_storage_account.data.id, role = "Storage Blob Data Contributor", who = "backend" } },
    var.azure_ai_account_id == "" ? {} : { "ai-backend" = {
    scope = var.azure_ai_account_id, role = "Cognitive Services OpenAI User", who = "backend" } },
  )
}

resource "azurerm_role_assignment" "r" {
  for_each             = local.role_assignments
  scope                = each.value.scope
  role_definition_name = each.value.role
  principal_id         = local.ids[each.value.who]
  principal_type       = "ServicePrincipal"
}

resource "time_sleep" "rbac" {
  depends_on      = [azurerm_role_assignment.r]
  create_duration = "60s"
}
