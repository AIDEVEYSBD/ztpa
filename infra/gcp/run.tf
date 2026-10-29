locals {
  backend_env = {
    NPR_ENV              = var.env
    NPR_FRR_MODE         = tostring(var.frr_mode)
    NPR_OTEL             = "gcp" # traces to Cloud Trace (roles/cloudtrace.agent)
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
    }, local.byok_env,
    # A rotation in progress: the old proxy secret is accepted too.
  nonsensitive(var.proxy_secret_previous) == "" ? {} : { NPR_PROXY_SECRET_PREVIOUS = "proxy-secret-previous" })

  frontend_ingress = var.domain == "" ? "INGRESS_TRAFFIC_ALL" : "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
}

# --- API: internal only; reached by the frontend through the VPC -------------
resource "google_cloud_run_v2_service" "api" {
  name                = "${local.n}-api"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  deletion_protection = false
  # Invoker IAM stays ON (many orgs enforce run.managed.requireInvokerIam): only
  # the frontend and migrate service accounts may call the API, with Google ID
  # tokens (frontend/middleware.ts, src/smoke.py), on top of internal ingress
  # and the proxy secret.
  labels = local.labels

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
        # ALL traffic through the VPC: the smoke test runs in this job and calls
        # the API's run.app URL, which internal ingress only admits from the VPC.
        egress = "ALL_TRAFFIC"
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
  name                = "${local.n}-web"
  location            = var.region
  ingress             = local.frontend_ingress
  deletion_protection = false
  # Invoker IAM on: callers need run.invoker (web_invokers below, or IAP on the
  # load balancer). Staging testers can use `gcloud run services proxy`.
  labels = local.labels

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
        for_each = merge({
          BACKEND_URL = google_cloud_run_v2_service.api.uri
          # The audience of the ID token the middleware attaches for the API's invoker IAM.
          NPR_BACKEND_AUDIENCE = google_cloud_run_v2_service.api.uri
          AUTH_URL             = var.app_url
          APP_URL              = var.app_url
          AUTH_TRUST_HOST      = "true"
          SSO_ISSUER           = var.sso_issuer
          SSO_CLIENT_ID        = var.sso_client_id
          SSO_ROLE_MAP         = var.sso_role_map
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

# --- who may invoke what ------------------------------------------------------------
resource "google_cloud_run_v2_service_iam_member" "api_invokers" {
  for_each = {
    frontend = google_service_account.frontend.email
    migrate  = google_service_account.migrate.email # the post-deploy smoke test calls /api/live
  }
  name     = google_cloud_run_v2_service.api.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${each.value}"
}

resource "google_cloud_run_v2_service_iam_member" "web_invokers" {
  for_each = toset(var.web_invokers)
  name     = google_cloud_run_v2_service.frontend.name
  location = var.region
  role     = "roles/run.invoker"
  member   = each.value
}
