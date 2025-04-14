@echo off
echo Installing Google Dorks Toolkit for Windows
python -m pip install --upgrade pip
pip install -r requirements.txt
echo Installation complete! You can run the toolkit using 'python dorker.py'.
pause
