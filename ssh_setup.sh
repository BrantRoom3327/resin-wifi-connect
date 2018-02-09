#!/bin/bash
set -e
eval "$(ssh-agent -s)"
ssh-add -K ~/.ssh/id_rsa_room3327
