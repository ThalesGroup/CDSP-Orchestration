terraform {
  required_providers {
    ciphertrust = {
      source = "thalesdocs.com/edu/ciphertrust"
    }
  }
}

provider "ciphertrust" {}

data "ciphertrust_init" "example" {}
