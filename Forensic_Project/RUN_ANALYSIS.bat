@echo off
cd /d "%~dp0"
python forensics.py report --case case
if errorlevel 1 pause & exit /b 1
start "" "case\reports\report.html"
