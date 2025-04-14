#!/bin/bash
echo "Installing Google Dorks Toolkit for Termux"
pkg update -y
pkg install python -y
pip install -r requirements.txt
chmod +x dorker.py
echo "Installation complete! You can run the toolkit using 'python dorker.py'."
