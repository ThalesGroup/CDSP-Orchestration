terraform {
  required_providers {
    ciphertrust = {
      source = "thalesdocs.com/edu/ciphertrust"
    }
  }
}

provider "ciphertrust" {
  address = "http://10.10.10.10"
  username = "admin"
  password = "pwd"
}

data "ciphertrust_users" "example" {}