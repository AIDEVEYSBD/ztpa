# Azure Front Door Premium + WAF in front of the frontend (set var.domain).
#
# Managed OWASP rules and bot protection in Prevention mode, a per-client-IP rate
# limit, HTTPS only. The frontend accepts only requests carrying this profile's
# X-Azure-FDID (NPR_EDGE_ID, enforced in frontend/middleware.ts), because a
# Container Apps ingress cannot restrict by the AzureFrontDoor.Backend service
# tag: without it, the app's own *.azurecontainerapps.io hostname would bypass
# the WAF. The health probe targets a static asset the middleware does not run on.

variable "domain" {
  description = "Custom domain served through Front Door + WAF. Empty = no Front Door (the frontend's own hostname is public)."
  type        = string
  default     = ""
}

variable "edge_rate_limit_per_minute" {
  type    = number
  default = 600
}

locals {
  fd = var.domain == "" ? 0 : 1
}

resource "azurerm_cdn_frontdoor_profile" "fd" {
  count               = local.fd
  name                = "afd-${local.n}"
  resource_group_name = azurerm_resource_group.rg.name
  sku_name            = "Premium_AzureFrontDoor"
  tags                = local.tags
}

resource "azurerm_cdn_frontdoor_endpoint" "web" {
  count                    = local.fd
  name                     = "fde-${local.n}-${random_string.suffix.result}"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.fd[0].id
  tags                     = local.tags
}

resource "azurerm_cdn_frontdoor_origin_group" "web" {
  count                    = local.fd
  name                     = "web"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.fd[0].id
  session_affinity_enabled = false

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    path                = "/icon.svg"
    protocol            = "Https"
    request_type        = "HEAD"
    interval_in_seconds = 30
  }
}

resource "azurerm_cdn_frontdoor_origin" "web" {
  count                          = local.fd
  name                           = "web"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.web[0].id
  enabled                        = true
  host_name                      = azurerm_container_app.frontend.ingress[0].fqdn
  origin_host_header             = azurerm_container_app.frontend.ingress[0].fqdn
  https_port                     = 443
  http_port                      = 80
  certificate_name_check_enabled = true
  priority                       = 1
  weight                         = 1000
}

resource "azurerm_cdn_frontdoor_custom_domain" "web" {
  count                    = local.fd
  name                     = replace(var.domain, ".", "-")
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.fd[0].id
  host_name                = var.domain
  tls {
    certificate_type = "ManagedCertificate"
  }
}

resource "azurerm_cdn_frontdoor_route" "web" {
  count                           = local.fd
  name                            = "web"
  cdn_frontdoor_endpoint_id       = azurerm_cdn_frontdoor_endpoint.web[0].id
  cdn_frontdoor_origin_group_id   = azurerm_cdn_frontdoor_origin_group.web[0].id
  cdn_frontdoor_origin_ids        = [azurerm_cdn_frontdoor_origin.web[0].id]
  cdn_frontdoor_custom_domain_ids = [azurerm_cdn_frontdoor_custom_domain.web[0].id]
  supported_protocols             = ["Http", "Https"]
  https_redirect_enabled          = true
  forwarding_protocol             = "HttpsOnly"
  patterns_to_match               = ["/*"]
  link_to_default_domain          = true
}

resource "azurerm_cdn_frontdoor_custom_domain_association" "web" {
  count                          = local.fd
  cdn_frontdoor_custom_domain_id = azurerm_cdn_frontdoor_custom_domain.web[0].id
  cdn_frontdoor_route_ids        = [azurerm_cdn_frontdoor_route.web[0].id]
}

resource "azurerm_cdn_frontdoor_firewall_policy" "waf" {
  count                             = local.fd
  name                              = "waf${replace(local.n, "-", "")}"
  resource_group_name               = azurerm_resource_group.rg.name
  sku_name                          = "Premium_AzureFrontDoor"
  enabled                           = true
  mode                              = "Prevention"
  request_body_check_enabled        = true
  custom_block_response_status_code = 403
  tags                              = local.tags

  custom_rule {
    name                           = "RatePerIp"
    enabled                        = true
    priority                       = 100
    type                           = "RateLimitRule"
    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = var.edge_rate_limit_per_minute
    action                         = "Block"
    match_condition {
      match_variable = "RemoteAddr"
      operator       = "IPMatch"
      match_values   = ["0.0.0.0/0", "::/0"]
    }
  }

  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"
  }

  managed_rule {
    type    = "Microsoft_BotManagerRuleSet"
    version = "1.1"
    action  = "Block"
  }
}

resource "azurerm_cdn_frontdoor_security_policy" "waf" {
  count                    = local.fd
  name                     = "waf"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.fd[0].id
  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.waf[0].id
      association {
        patterns_to_match = ["/*"]
        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_custom_domain.web[0].id
        }
        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_endpoint.web[0].id
        }
      }
    }
  }
}

output "front_door_endpoint" {
  description = "CNAME the custom domain to this (only with var.domain); add the TXT validation record from the portal or `az afd custom-domain show`."
  value       = var.domain == "" ? null : azurerm_cdn_frontdoor_endpoint.web[0].host_name
}
