# Ansible Collection
For IT admins and DevOps teams who use Red Hat® Ansible® to manage their infrastructure, we have provided Ansible Modules and Playbooks that interfaces with each of the products within the CipherTrust Data Security Platform and IBM Guardium Data Encryption.

## Ansible version compatibility
Tested with the Ansible Core 2.12, and 2.13 releases, and the current development version of Ansible. Ansible Core versions before 2.11.0 are not tested.

## Python version compatibility
Tested with Python version 3.6

## Installing this collection
Install Ansible on your host machine using instructions specific to the OS of the host machine.

Download thales-ciphertrust-1.0.0.tar.gz from this repository
* [Ansible](/)

Install the collection using command -
```
ansible-galaxy collection install thales-ciphertrust-1.0.0.tar.gz
```

## Using this collection
You can call modules by their Fully Qualified Collection Name (FQCN), such as thalesgroup.ciphertrust.cm_cluster

```
---
- name: "Create new cluster"
  thalesgroup.ciphertrust.cm_cluster:
    localNode:
      server_ip: "{{ <IP or FQDN of CipherTrust Manager Server> }}"
      server_private_ip: "{{ <Private IP of CipherTrust Manager Server...If different from server_ip> }}"
      server_port: "{{ port number where CipherTrust Manager is listening, defaults to 5432}}"
      user: "{{ <Admin User of CipherTrust Manager> }}"
      password: "{{ <Password of Admin User> }}"
      verify: False
    op_type: new
```

## Run Playbooks
Sample playbooks provided as part of the repo
* [Ansible](playbooks/)
```
ansible-playbook cluster.yml -vv
```

## Contributing to this collection
We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the this repository.
