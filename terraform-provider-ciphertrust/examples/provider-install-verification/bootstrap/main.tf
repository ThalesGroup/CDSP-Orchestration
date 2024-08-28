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
  bootstrap = var.bootstrap
}

resource "ciphertrust_cm_ssh_key" "sshKey" {
  key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIVGP8Ojyum6d7/r2Q1oihXfEcmEgzKUOCcNue2ovIRaxnqdFBTIEVnPBu6R0kMvBHvhyYpqQaLyCa6QhYgmzLA16A7M0+QSdBz+pFC6cMF6VK9b/lXgLek3aD4s+ynCc+/RF+n2AcS5j+JmkvQeOntY/WhmvCwJJpk6cmNfpnqfF/C8ExvGC3IPBCaVtHU2eIHvT0rIVwGYNZulrryeoPQZ2vH4cUPCDHxFeWTGCjXxPvy0JSoY0Z5mKJtxWLnEgIFzTUYiDueKM7HTrj5LPzov3ohB5bhNdiA+wLljFL7da8OvNhXp6aqCgg9ezs8df3bNSkWiaf24R/28sTeDuF"
}
output "ssh_key_update" {
  value = ciphertrust_cm_ssh_key.sshKey
}

resource "ciphertrust_cm_user_password_change" "changePwd" {
  username = "admin"
  password = "admin"
  new_password = "ChangeIt01!"
}
output "user_change_pwd" {
  value = ciphertrust_cm_user_password_change.changePwd
}