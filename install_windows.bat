@echo off
echo Installing PDF Scanner requirements offline (Windows)...
REM Change to the folder with .whl files
cd /d %~dp0

REM Install all packages from the local 'packages' directory
pip install --no-index --find-links=packages -r requirements.txt

echo Installation complete. You can now run part2.py with:
echo python part2.py
pause
