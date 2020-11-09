#!/bin/bash
IFACE="wlp4s0"
CHAN=3
sudo airmon-ng check kill
sudo airmon-ng start ${IFACE}
sudo iwconfig wlp4s0mon chan ${CHAN}
python3 analyze.py
sudo airmon-ng stop ${IFACE}mon
sudo ip link set dev ${IFACE} up
sudo service NetworkManager restart

