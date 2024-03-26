terraform {
  required_providers {
    ciphertrust = {
      source = "thalesdocs.com/edu/ciphertrust"
    }
  }
}

provider "ciphertrust" {
  address = "https://10.10.10.10"
  username = "admin"
  password = "ChangeIt01!"
}

data "ciphertrust_users" "cm_users" {}

resource "ciphertrust_cm_user" "new_user" {
  email = "sample@local.com"
  name = "Sample User"
  nickname = "sample"
  username = "user"
  password = ChangeIt01!
}

output "list" {
  value = data.ciphertrust_users.cm_users
}

output "create" {
  value = ciphertrust_cm_user.new_user
}