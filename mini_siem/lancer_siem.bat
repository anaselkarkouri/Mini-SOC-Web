
@echo off
title Mini-SIEM - En cours d execution
echo Demarrage du Mini-SIEM...
timeout /t 10 /nobreak
cd /d C:\xampp\htdocs\mini_m2\mini_siem
python mini_siem.py
pause