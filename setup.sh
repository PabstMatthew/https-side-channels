#!/bin/bash
sudo apt-get update
sudo apt-get install -y aircrack-ng python3-dev firefox
sudo pip3 install -r requirements.txt
wget https://github.com/mozilla/geckodriver/releases/download/v0.28.0/geckodriver-v0.28.0-linux64.tar.gz
tar -xvzf geckodriver-v0.28.0-linux64.tar.gz
rm geckodriver-v0.28.0-linux64.tar.gz
chmod +x geckodriver
sudo mv geckodriver /usr/bin/
