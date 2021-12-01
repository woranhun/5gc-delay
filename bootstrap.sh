#!/usr/bin/env bash

########################### Virtualenv setup ####################################

# check existance of virtualenv command
if ! command -v virtualenv &>/dev/null; then
  echo "This command needs virtualenv to run."
  echo "Install it like this:"
  printf "\tpip3 install --user virtualenv\n"
  printf "\texport PATH=\"~/.local/bin:\$PATH\"\n"
  exit 1
fi

# create virtualenv if not present
[[ ! -d .venv ]] && virtualenv .venv

source .venv/bin/activate
pip3 install -r requirements.txt

# to stay in our comfy virtualenv
exec "${SHELL:bash}"
