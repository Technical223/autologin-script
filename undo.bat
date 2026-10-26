@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0autologin.ps1" -Undo -Pause
