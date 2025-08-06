#!/bin/bash
python3 ./main.py ./motivating-example/react -t xss --timeout 120 --run-env ./tmp_env --log-base-location ./tmp_log --babel ./motivating-example/react --export all --is-jsx-application --service-entry ./motivating-example/API/index.js
