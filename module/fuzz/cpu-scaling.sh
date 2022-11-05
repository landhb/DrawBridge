#!/bin/bash

if [[ $1 == "on" ]]; then
    echo "[*] turning on performance mode for fuzzing"
    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
else
    echo "[*] going back to powersaving mode"
    echo powersave | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
fi
