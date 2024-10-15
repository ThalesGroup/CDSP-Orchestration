terraform {
  required_providers {
    ciphertrust = {
      source = "thalesdocs.com/edu/ciphertrust"
    }
  }
}

# Start: Configure the CM provider using vars such as CM IP/FQDN, Username, Password
# bootstrap in this example shall be no since CM is already expected to be running and bootstraped
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
  username = var.cm_username
  password = var.cm_password
}
# End: Configure the CM provider using vars such as CM IP/FQDN, Username, Password

# Create a registration token for the CTE client to talk to CM
## First get the CA ID from the subject DN (need to be URL encoded)
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

# Get the user ID from the username
data "ciphertrust_cm_users_list" "users_list" {
  filters = {
    username = var.cm_username
  }
}

# Create a key on CipherTrust Manager to perform transparent encryption operation
resource "ciphertrust_cm_key" "cte_key" {
  name="terraform"
  algorithm="aes"
  size=256
  usage_mask=76
  undeletable=false
  unexportable=false
  meta={
    owner_id=tolist(data.ciphertrust_cm_users_list.users_list.users)[0].user_id
    permissions={
      decrypt_with_key=["CTE Clients"]
      encrypt_with_key=["CTE Clients"]
      export_key=["CTE Clients"]
      mac_verify_with_key=["CTE Clients"]
      mac_with_key=["CTE Clients"]
      read_key=["CTE Clients"]
      sign_verify_with_key=["CTE Clients"]
      sign_with_key=["CTE Clients"]
      use_key=["CTE Clients"]
    }
    cte={
      persistent_on_client=true
      encryption_mode="CBC"
      cte_versioned=false
    }
    xts=false
  }
}

output "create" {
  value = ciphertrust_cm_key.cte_key
}