terraform {
  required_providers {
    ciphertrust = {
      source = "thalesdocs.com/edu/ciphertrust"
    }
  }
}

variable "cm_ip" {
  description = "FQDN of the CM instance"
  type        = string
}
variable "cm_username" {
  description = "FQDN of the CM instance"
  type        = string
}
variable "cm_password" {
  description = "FQDN of the CM instance"
  type        = string
}
variable "bootstrap" {
  description = "FQDN of the CM instance"
  type        = string
}

provider "ciphertrust" {
  address = var.cm_ip
  username = var.cm_username
  password = var.cm_password
  bootstrap = var.bootstrap
}

provider "null" {
  # No configuration needed
}

data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    subject = "%2FC%3DUS%2FST%3DTX%2FL%3DAustin%2FO%3DThales%2FCN%3DCipherTrust%20Root%20CA"
  }
}

output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}

resource "ciphertrust_cm_reg_token" "reg_token" {
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}

data "ciphertrust_cm_tokens_list" "tokens_list" {
  filters = {
    id = ciphertrust_cm_reg_token.reg_token.id
  }
}

output "reg_token_value" {
  value = tolist(data.ciphertrust_cm_tokens_list.tokens_list.tokens)[0].id
}