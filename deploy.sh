#!/bin/bash
ansible-playbook -i ./ansible/inventory/hosts ansible/main.yml --ask-vault-pass
