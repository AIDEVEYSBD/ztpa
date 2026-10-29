resource "google_sql_database_instance" "pg" {
  name                = local.n
  database_version    = "POSTGRES_16"
  region              = var.region
  deletion_protection = true
  depends_on          = [google_service_networking_connection.psa]

  settings {
    tier              = var.db_tier
    edition           = "ENTERPRISE"
    availability_type = var.db_high_availability ? "REGIONAL" : "ZONAL"
    disk_type         = "PD_SSD"
    disk_autoresize   = true
    user_labels       = local.labels

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "02:00"
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 14
      }
    }

    maintenance_window {
      day  = 7
      hour = 3
    }

    insights_config {
      query_insights_enabled = true
    }

    # Budget: api instances x processes x DB_POOL_MAX (8) + worker instances x
    # slots x 2 must stay below this, with headroom for migrations and admin.
    database_flags {
      name  = "max_connections"
      value = tostring(var.db_max_connections)
    }
  }
}

resource "google_sql_database" "app" {
  name     = "npr"
  instance = google_sql_database_instance.pg.name
}

# Two identities. `npr_admin` (a Cloud SQL user, so a cloudsqlsuperuser member)
# owns the schema and is used ONLY by the migrate job. `npr_app` is created by
# that job (`migrate.py --ensure-app-role`) with row access to the product
# schema and nothing else; the API, worker and frontend connect as it.
resource "random_password" "db_admin" {
  length  = 40
  special = false
}

resource "random_password" "db_app" {
  length  = 40
  special = false
}

resource "google_sql_user" "admin" {
  name     = "npr_admin"
  instance = google_sql_database_instance.pg.name
  password = random_password.db_admin.result
}

locals {
  db_host            = google_sql_database_instance.pg.private_ip_address
  database_url       = "postgresql://npr_app:${random_password.db_app.result}@${local.db_host}:5432/${google_sql_database.app.name}?sslmode=require"
  database_admin_url = "postgresql://${google_sql_user.admin.name}:${random_password.db_admin.result}@${local.db_host}:5432/${google_sql_database.app.name}?sslmode=require"
}
