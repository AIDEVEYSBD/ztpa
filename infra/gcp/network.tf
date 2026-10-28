# Private networking. Cloud SQL has no public IP; the API is reachable only from
# inside the VPC; the frontend sends ALL its egress through the VPC so its calls
# to the API's run.app URL count as internal traffic (Private Google Access on
# the subnet), and reaches the internet (the SSO issuer) through Cloud NAT.

resource "google_compute_network" "vpc" {
  name                    = local.n
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "run" {
  name                     = "${local.n}-run"
  network                  = google_compute_network.vpc.id
  region                   = var.region
  ip_cidr_range            = "10.20.0.0/24"
  private_ip_google_access = true
}

resource "google_compute_global_address" "psa" {
  name          = "${local.n}-psa"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.vpc.id
}

resource "google_service_networking_connection" "psa" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.psa.name]
}

resource "google_compute_router" "nat" {
  name    = "${local.n}-nat"
  network = google_compute_network.vpc.id
  region  = var.region
}

resource "google_compute_router_nat" "nat" {
  name                               = "${local.n}-nat"
  router                             = google_compute_router.nat.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
