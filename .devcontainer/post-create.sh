#!/bin/bash
eval "$(direnv hook bash)" >> ~/.bashrc
direnv allow .
source ~/.bashrc