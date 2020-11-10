#!/bin/bash
IFACE="wlp4s0"
CHAN=3
TARGET="192.168.144.154"
sudo airmon-ng check kill
sudo airmon-ng start ${IFACE}
sudo iwconfig ${IFACE}mon chan ${CHAN}
python3 analyze.py -i ${IFACE} -t ${TARGET}
sudo airmon-ng stop ${IFACE}mon
sudo ip link set dev ${IFACE} up
sudo service NetworkManager restart

