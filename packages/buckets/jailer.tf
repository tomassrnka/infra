# Jailer versions bucket - stores pre-built jailer binaries
# Based on the pattern from fc_versions_bucket

resource "google_storage_bucket" "jailer_versions_bucket" {
  location                    = var.gcp_region
  name                        = "${var.gcp_project_id}-jailer-versions"
  project                     = var.gcp_project_id
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"

  versioning {
    enabled = false
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 365
    }
  }

  cors {
    max_age_seconds = 3600
    method = [
      "GET",
      "HEAD",
    ]
    origin = [
      "*",
    ]
    response_header = [
      "*",
    ]
  }
}

# Output for reference
output "jailer_versions_bucket_name" {
  value = google_storage_bucket.jailer_versions_bucket.name
}

output "jailer_versions_bucket_url" {
  value = google_storage_bucket.jailer_versions_bucket.url
}