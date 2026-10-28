locals {
  backend_env = {
    NPR_ENV              = var.env
    NPR_FRR_MODE         = tostring(var.frr_mode)
    NPR_PLATFORM         = "gcp"
    NPR_JOBS_INLINE      = "false"
    NPR_STORAGE_URL      = "gs://${google_storage_bucket.data.name}/frr"
    FRONTEND_ORIGIN      = var.app_url
    ADVISORY_PROVIDER    = var.advisory_provider
    VERTEX_PROJECT       = var.project_id
    VERTEX_LOCATION      = var.vertex_location
    VERTEX_MODEL         = var.vertex_model
    GOOGLE_CLOUD_PROJECT = var.project_id
    DB_POOL_MAX          = "8"
  }
  backend_secret_env = merge({
    DATABASE_URL     = "database-url"
    NPR_PROXY_SECRET = "proxy-secret"
    NPR_ARTIFACT_KEY = "artifact-key"
  }, local.byok_env)

  frontend_ingress = var.domain == "" ? "INGRESS_TRAFFIC_ALL" : "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
}

# --- API: internal only; reached by the frontend through the VPC -------------
resource "google_cloud_run_v2_service" "api" {
  name                 = "${local.n}-api"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  invoker_iam_disabled = true # network-restricted to the VPC; identity is the proxy secret + SSO headers
  deletion_protection  = false
  labels               = local.labels

  template {
    service_account                  = google_service_account.backend.email
    max_instance_request_concurrency = 40
    timeout                          = "60s"

    scaling {
      min_instance_count = var.api_min_instances
      max_instance_count = var.api_max_instances
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.run.id
      }
    }

    containers {
      image = var.backend_image
      ports { container_port = 8000 }

      resources {
        limits            = { cpu = tostring(max(2, var.api_processes)), memory = "2Gi" }
        startup_cpu_boost = true
      }

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
          name = env.key
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.s[env.value].secret_id
              version = "latest"
            }
          }
        }
      }

      startup_probe {
        http_get { path = "/api/live" }
        period_seconds    = 3
        failure_threshold = 20
      }
      liveness_probe {
        http_get { path = "/api/live" }
        period_seconds = 15
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.backend, google_secret_manager_secret_version.s]
}

# --- worker: consumes the job queue; always-on CPU, no callers ---------------
resource "google_cloud_run_v2_service" "worker" {
  name                = "${local.n}-worker"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  deletion_protection = false
  labels              = local.labels

  template {
    service_account = google_service_account.backend.email

    scaling {
      min_instance_count = var.worker_min_instances
      max_instance_count = var.worker_max_instances
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.run.id
      }
    }

    containers {
      image   = var.backend_image
      command = ["python", "-m", "src.jobs.worker"]
      args    = ["--concurrency", tostring(var.worker_concurrency), "--health-port", "8080"]
      ports { container_port = 8080 }

      resources {
        limits   = { cpu = "2", memory = "4Gi" }
        cpu_idle = false # polling the queue needs CPU between requests
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
          name = env.key
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.s[env.value].secret_id
              version = "latest"
            }
          }
        }
      }

      startup_probe {
        http_get { path = "/" }
        period_seconds    = 3
        failure_threshold = 20
      }
      liveness_probe {
        http_get { path = "/" }
        period_seconds = 30
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.backend, google_secret_manager_secret_version.s]
}

# --- migrate: one-shot job, run by CI before each deploy ---------------------
resource "google_cloud_run_v2_job" "migrate" {
  name                = "${local.n}-migrate"
  location            = var.region
  deletion_protection = false
  labels              = local.labels

  template {
    task_count = 1
    template {
      service_account = google_service_account.migrate.email
      max_retries     = 1
      timeout         = "900s"

      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"
        network_interfaces {
          network    = google_compute_network.vpc.id
          subnetwork = google_compute_subnetwork.run.id
        }
      }

      containers {
        image = var.backend_image
        # Command and args split so a one-off execution can override the args:
        # CI runs the post-deploy smoke test as `--args=-m,src.smoke,...`.
        command = ["python"]
        args    = ["/app/db/migrate.py", "--bootstrap", "--ensure-app-role"]
        env {
          name = "DATABASE_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.s["database-admin-url"].secret_id
              version = "latest"
            }
          }
        }
        env {
          name = "NPR_APP_DB_PASSWORD"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.s["app-db-password"].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.migrate, google_secret_manager_secret_version.s]
}

# --- frontend: the one public entry ------------------------------------------
resource "google_cloud_run_v2_service" "frontend" {
  name                 = "${local.n}-web"
  location             = var.region
  ingress              = local.frontend_ingress
  invoker_iam_disabled = true
  deletion_protection  = false
  labels               = local.labels

  template {
    service_account                  = google_service_account.frontend.email
    max_instance_request_concurrency = 80

    scaling {
      min_instance_count = var.frontend_min_instances
      max_instance_count = var.frontend_max_instances
    }

    # ALL egress through the VPC: the API's internal ingress only admits
    # traffic that arrives from the VPC. Internet egress (SSO issuer) uses NAT.
    vpc_access {
      egress = "ALL_TRAFFIC"
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.run.id
      }
    }

    containers {
      image = var.frontend_image
      ports { container_port = 3000 }

      resources {
        limits = { cpu = "1", memory = "1Gi" }
      }

      dynamic "env" {
        for_each = {
          BACKEND_URL     = google_cloud_run_v2_service.api.uri
          AUTH_URL        = var.app_url
          APP_URL         = var.app_url
          AUTH_TRUST_HOST = "true"
          SSO_ISSUER      = var.sso_issuer
          SSO_CLIENT_ID   = var.sso_client_id
          SSO_ROLE_MAP    = var.sso_role_map
        }
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = {
          AUTH_SECRET       = "auth-secret"
          NPR_PROXY_SECRET  = "proxy-secret"
          DATABASE_URL      = "database-url"
          SSO_CLIENT_SECRET = "sso-client-secret"
        }
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.s[env.value].secret_id
              version = "latest"
            }
          }
        }
      }

      startup_probe {
        tcp_socket { port = 3000 }
        period_seconds    = 3
        failure_threshold = 20
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.frontend, google_compute_router_nat.nat]
}
