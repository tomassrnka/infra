variable "prefix" {
  type = string
}

variable "gcp_project_id" {
  description = "The project to deploy the cluster in"
  type        = string
}

variable "gcp_region" {
  type = string
}
