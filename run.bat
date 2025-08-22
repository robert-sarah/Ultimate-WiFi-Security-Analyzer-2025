@echo off
echo ==========================================
echo Analyseur WiFi Professionnel - Noah AI
echo ==========================================
echo.

REM Vérifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERREUR: Python n'est pas installé ou non accessible dans PATH
    pause
    exit /b 1
)

REM Vérifier les dépendances Python
echo Vérification des dépendances Python...
pip install -r src/python/requirements.txt

REM Créer les répertoires nécessaires
echo Création des répertoires...
if not exist "build" mkdir build
if not exist "exports" mkdir exports
if not exist "logs" mkdir logs

REM Compiler le module C++
echo Compilation du module C++...
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
if errorlevel 1 (
    echo ERREUR: Échec de compilation du module C++
    pause
    exit /b 1
)
cd ..

REM Copier le module compilé
echo Installation du module...
copy "build\Release\wifi_core_cpp.pyd" "src\python\" >nul 2>&1
copy "build\wifi_core_cpp.pyd" "src\python\" >nul 2>&1

REM Lancer l'application
echo.
echo ==========================================
echo Lancement de l'application...
echo ==========================================
cd src/python
python main.py

pause