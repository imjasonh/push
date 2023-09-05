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

resource "google_secret_manager_secret" "private-key" {
  secret_id = "private-key"
  replication { automatic = true }
}

resource "google_secret_manager_secret_version" "private-key" {
  secret      = google_secret_manager_secret.private-key.name
  secret_data = file("private.pem")
}

resource "google_service_account" "sa" {
  account_id = "push-sa"
}

resource "google_secret_manager_secret_iam_member" "access-private-key" {
  secret_id  = google_secret_manager_secret.private-key.secret_id
  role       = "roles/secretmanager.secretAccessor"
  member     = "serviceAccount:${google_service_account.sa.email}"
  depends_on = [google_secret_manager_secret.private-key]
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

    volumes {
      name = "secret-volume"
      secret {
        secret = google_secret_manager_secret.private-key.secret_id
        items {
          version = "latest"
          path    = "private.pem"
          mode    = 0 # use default 0444
        }
      }
    }
    containers {
      image = ko_build.app.image_ref
      volume_mounts {
        name       = "secret-volume"
        mount_path = "/secret"
      }
      env {
        name  = "PRIVATE_KEY_PATH"
        value = "/secret/private.pem"
      }
    }
  }
}

output "url" {
  value = google_cloud_run_v2_service.app.uri
}
