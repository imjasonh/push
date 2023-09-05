terraform {
  required_providers {
    ko = { source = "ko-build/ko" }
  }
}

provider "ko" {
  repo = "gcr.io/${var.project}/push"
}
provider "google" {
  project = var.project
}

variable "project" {}
variable "region" { default = "us-east4" }

resource "ko_build" "app" {
  importpath = "push"
}

locals {
  secrets = {
    "private-key" : trimspace(file("private.pem"))
    "gh-client-id" : trimspace(file("gh-client-id"))
    "gh-secret" : trimspace(file("gh-secret"))
  }
}

resource "google_secret_manager_secret" "secret" {
  for_each  = local.secrets
  secret_id = each.key
  replication { automatic = true }
}

resource "google_secret_manager_secret_version" "secret" {
  for_each    = local.secrets
  secret      = google_secret_manager_secret.secret[each.key].name
  secret_data = each.value
}

resource "google_service_account" "sa" {
  account_id = "push-sa"
}

resource "google_secret_manager_secret_iam_member" "access-secret" {
  for_each = local.secrets

  secret_id = google_secret_manager_secret.secret[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa.email}"
}

// Anybody can invoke the service.
resource "google_cloud_run_v2_service_iam_binding" "public" {
  location = google_cloud_run_v2_service.app.location
  name     = google_cloud_run_v2_service.app.name
  role     = "roles/run.invoker"
  members  = ["allUsers"]
}

resource "google_cloud_run_v2_service" "app" {
  name     = "push"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.sa.email

    containers {
      image = ko_build.app.image_ref

      dynamic "env" {
        for_each = local.secrets
        content {
          name = upper(replace(env.key, "-", "_"))
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.secret[env.key].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }
}

output "url" {
  value = google_cloud_run_v2_service.app.uri
}
