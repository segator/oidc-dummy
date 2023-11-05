#!/bin/bash
direnv allow .
eval "$(direnv hook bash)" >> ~/.bashrc
source ~/.bashrc