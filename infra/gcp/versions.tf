terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # State holds generated secrets (proxy, artifact, auth, DB password). Keep it
  # in a dedicated bucket with versioning and access limited to the deployers:
  #
  #   terraform init -backend-config="bucket=<state-bucket>" -backend-config="prefix=frr/<env>"
  backend "gcs" {}
}

provider "google" {
  project = var.project_id
  region  = var.region
}
