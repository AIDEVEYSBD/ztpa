# Baseline alerts. Notification channels are attached by the operator
# (var.alert_channels), so this works before anyone has decided where pages go.

variable "alert_channels" {
  description = "Monitoring notification channel ids to page."
  type        = list(string)
  default     = []
}

resource "google_monitoring_alert_policy" "api_5xx" {
  display_name          = "${local.n} API 5xx rate"
  combiner              = "OR"
  notification_channels = var.alert_channels
  conditions {
    display_name = "5xx > 2% for 5 min"
    condition_monitoring_query_language {
      duration = "300s"
      query    = <<-EOT
        fetch cloud_run_revision
        | metric 'run.googleapis.com/request_count'
        | filter resource.service_name == '${google_cloud_run_v2_service.api.name}'
        | align rate(1m)
        | every 1m
        | group_by [], [errors: sum(if(metric.response_code_class == '5xx', val(), 0)), total: sum(val())]
        | value [ratio: errors / total]
        | condition ratio > 0.02
      EOT
    }
  }
}

resource "google_monitoring_alert_policy" "queue_stalled" {
  display_name          = "${local.n} job worker down"
  combiner              = "OR"
  notification_channels = var.alert_channels
  conditions {
    display_name = "no worker instance for 5 min"
    condition_absent {
      duration = "300s"
      filter   = "resource.type = \"cloud_run_revision\" AND resource.labels.service_name = \"${google_cloud_run_v2_service.worker.name}\" AND metric.type = \"run.googleapis.com/container/instance_count\""
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MAX"
      }
    }
  }
}

resource "google_monitoring_alert_policy" "db_cpu" {
  display_name          = "${local.n} database CPU"
  combiner              = "OR"
  notification_channels = var.alert_channels
  conditions {
    display_name = "CPU > 80% for 10 min"
    condition_threshold {
      filter          = "resource.type = \"cloudsql_database\" AND resource.labels.database_id = \"${var.project_id}:${google_sql_database_instance.pg.name}\" AND metric.type = \"cloudsql.googleapis.com/database/cpu/utilization\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
      duration        = "600s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
}
