#!/bin/bash

unbuffer bash -c '(while true; do ./ovenctl_telemetry.py -H 10.1.246.117 -Q; sleep 10; done)' | tee telemetry.log

