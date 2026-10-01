@echo off
rem Startet das Einrichtungsfenster (fragt nach Adminrechten)
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0NspLetsEncrypt.ps1"
