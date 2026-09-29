@echo off
rem Pornește tot proiectul cu dublu-click: creează mediul, instalează pachetele, rulează experimentul.
setlocal
cd /d "%~dp0"

if not exist .venv (
    echo Creez mediul virtual...
    py -3.12 -m venv .venv 2>nul || py -3 -m venv .venv 2>nul || python -m venv .venv
)
if not exist .venv\Scripts\python.exe (
    echo Nu am gasit Python. Instaleaza Python 3.12 de pe python.org si ruleaza din nou.
    pause
    exit /b 1
)

echo Instalez pachetele...
.venv\Scripts\python.exe -m pip install --quiet -r requirements.txt
if errorlevel 1 (
    echo Instalarea a esuat. Vezi mesajul de mai sus.
    pause
    exit /b 1
)

echo Rulez experimentul...
.venv\Scripts\python.exe -m detectie_bruteforce.run_experiment --n-seeds 5
echo.
echo Gata. Rezultatele sunt in folderul results\
pause
