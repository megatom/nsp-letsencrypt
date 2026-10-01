@echo off
rem Startet das Einrichtungsfenster ohne Konsolenfenster (fragt nach Adminrechten)
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0NspLetsEncrypt.ps1"
