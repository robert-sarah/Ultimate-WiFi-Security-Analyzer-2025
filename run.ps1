# Analyseur WiFi Professionnel - Noah AI
# Script PowerShell de démarrage

Write-Host "==========================================" -ForegroundColor Green
Write-Host "Analyseur WiFi Professionnel - Noah AI" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

# Vérifier Python
try {
    $pythonVersion = python --version
    Write-Host "✓ Python détecté: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ ERREUR: Python n'est pas installé ou non accessible dans PATH" -ForegroundColor Red
    Read-Host "Appuyez sur Entrée pour quitter..."
    exit 1
}

# Vérifier les dépendances Python
Write-Host "Vérification des dépendances Python..." -ForegroundColor Yellow
try {
    pip install -r src\python\requirements.txt
    Write-Host "✓ Dépendances installées" -ForegroundColor Green
} catch {
    Write-Host "✗ ERREUR: Échec de l'installation des dépendances" -ForegroundColor Red
    Read-Host "Appuyez sur Entrée pour quitter..."
    exit 1
}

# Créer les répertoires nécessaires
Write-Host "Création des répertoires..." -ForegroundColor Yellow
$directories = @("build", "exports", "logs")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "✓ Répertoire créé: $dir" -ForegroundColor Green
    }
}

# Compiler le module C++
Write-Host "Compilation du module C++..." -ForegroundColor Yellow
Set-Location build

try {
    cmake .. -DCMAKE_BUILD_TYPE=Release
    cmake --build . --config Release
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Compilation réussie" -ForegroundColor Green
    } else {
        throw "Échec de compilation"
    }
} catch {
    Write-Host "✗ ERREUR: Échec de compilation du module C++" -ForegroundColor Red
    Set-Location ..
    Read-Host "Appuyez sur Entrée pour quitter..."
    exit 1
}

Set-Location ..

# Copier le module compilé
Write-Host "Installation du module..." -ForegroundColor Yellow
$modulePaths = @(
    "build\Release\wifi_core_cpp.pyd",
    "build\wifi_core_cpp.pyd",
    "build\lib\wifi_core_cpp.pyd"
)

$moduleCopied = $false
foreach ($path in $modulePaths) {
    if (Test-Path $path) {
        Copy-Item $path "src\python\" -Force
        Write-Host "✓ Module copié: $path" -ForegroundColor Green
        $moduleCopied = $true
        break
    }
}

if (-not $moduleCopied) {
    Write-Host "⚠ Attention: Module non trouvé, lancement en mode démo..." -ForegroundColor Yellow
}

# Lancer l'application
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Lancement de l'application..." -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

Set-Location src\python
python main.ps1

Write-Host ""
Write-Host "Application fermée" -ForegroundColor Yellow
Read-Host "Appuyez sur Entrée pour quitter..."