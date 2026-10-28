# Optional global HTTPS load balancer in front of the frontend (set var.domain).
# Managed certificate, HTTP->HTTPS redirect, and a Cloud Armor policy with a
# per-client-IP rate limit and the preconfigured OWASP rules in preview mode
# (switch to enforce after reviewing their logs against real traffic).

locals {
  edge = var.domain == "" ? 0 : 1
}

resource "google_compute_region_network_endpoint_group" "web" {
  count                 = local.edge
  name                  = "${local.n}-web"
  region                = var.region
  network_endpoint_type = "SERVERLESS"
  cloud_run {
    service = google_cloud_run_v2_service.frontend.name
  }
}

resource "google_compute_security_policy" "edge" {
  count = local.edge
  name  = "${local.n}-edge"

  rule {
    action   = "throttle"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config { src_ip_ranges = ["*"] }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.edge_rate_limit_per_minute
        interval_sec = 60
      }
    }
  }

  rule {
    action   = "deny(403)"
    priority = 2000
    preview  = true
    match {
      expr { expression = "evaluatePreconfiguredWaf('sqli-v33-stable') || evaluatePreconfiguredWaf('xss-v33-stable')" }
    }
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config { src_ip_ranges = ["*"] }
    }
  }
}

resource "google_compute_backend_service" "web" {
  count                 = local.edge
  name                  = "${local.n}-web"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  security_policy       = google_compute_security_policy.edge[0].id
  log_config {
    enable      = true
    sample_rate = 1.0
  }
  backend {
    group = google_compute_region_network_endpoint_group.web[0].id
  }
}

resource "google_compute_url_map" "web" {
  count           = local.edge
  name            = "${local.n}-web"
  default_service = google_compute_backend_service.web[0].id
}

resource "google_compute_managed_ssl_certificate" "web" {
  count = local.edge
  name  = "${local.n}-web"
  managed { domains = [var.domain] }
}

resource "google_compute_target_https_proxy" "web" {
  count            = local.edge
  name             = "${local.n}-web"
  url_map          = google_compute_url_map.web[0].id
  ssl_certificates = [google_compute_managed_ssl_certificate.web[0].id]
}

resource "google_compute_global_address" "web" {
  count = local.edge
  name  = "${local.n}-web"
}

resource "google_compute_global_forwarding_rule" "https" {
  count                 = local.edge
  name                  = "${local.n}-https"
  target                = google_compute_target_https_proxy.web[0].id
  ip_address            = google_compute_global_address.web[0].address
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

resource "google_compute_url_map" "redirect" {
  count = local.edge
  name  = "${local.n}-redirect"
  default_url_redirect {
    https_redirect = true
    strip_query    = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  count   = local.edge
  name    = "${local.n}-redirect"
  url_map = google_compute_url_map.redirect[0].id
}

resource "google_compute_global_forwarding_rule" "http" {
  count                 = local.edge
  name                  = "${local.n}-http"
  target                = google_compute_target_http_proxy.redirect[0].id
  ip_address            = google_compute_global_address.web[0].address
  port_range            = "80"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}
