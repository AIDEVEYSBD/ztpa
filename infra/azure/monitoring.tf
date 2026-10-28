resource "azurerm_monitor_action_group" "ops" {
  count               = length(var.alert_emails) > 0 ? 1 : 0
  name                = "ag-${local.n}"
  resource_group_name = azurerm_resource_group.rg.name
  short_name          = substr("frr${var.env}", 0, 12)

  dynamic "email_receiver" {
    for_each = var.alert_emails
    content {
      name          = "email-${email_receiver.key}"
      email_address = email_receiver.value
    }
  }
}

locals {
  action_groups = [for g in azurerm_monitor_action_group.ops : g.id]
}

resource "azurerm_monitor_metric_alert" "api_5xx" {
  name                = "${local.n}-api-5xx"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_container_app.api.id]
  description         = "API answering 5xx"
  frequency           = "PT1M"
  window_size         = "PT5M"
  severity            = 2

  criteria {
    metric_namespace = "Microsoft.App/containerApps"
    metric_name      = "Requests"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 20
    dimension {
      name     = "statusCodeCategory"
      operator = "Include"
      values   = ["5xx"]
    }
  }

  dynamic "action" {
    for_each = local.action_groups
    content { action_group_id = action.value }
  }
}

resource "azurerm_monitor_metric_alert" "db_cpu" {
  name                = "${local.n}-db-cpu"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_postgresql_flexible_server.pg.id]
  description         = "Database CPU above 80% for 10 minutes"
  frequency           = "PT1M"
  window_size         = "PT15M"
  severity            = 2

  criteria {
    metric_namespace = "Microsoft.DBforPostgreSQL/flexibleServers"
    metric_name      = "cpu_percent"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 80
  }

  dynamic "action" {
    for_each = local.action_groups
    content { action_group_id = action.value }
  }
}

resource "azurerm_monitor_metric_alert" "worker_down" {
  name                = "${local.n}-worker-down"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_container_app.worker.id]
  description         = "No worker replica running: queued jobs will not start"
  frequency           = "PT1M"
  window_size         = "PT5M"
  severity            = 1

  criteria {
    metric_namespace = "Microsoft.App/containerApps"
    metric_name      = "Replicas"
    aggregation      = "Maximum"
    operator         = "LessThan"
    threshold        = 1
  }

  dynamic "action" {
    for_each = local.action_groups
    content { action_group_id = action.value }
  }
}
