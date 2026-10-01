# Paket-bauen.ps1
# Erzeugt NspLetsEncrypt.zip im Projektordner: alle Dateien für den Server in einem Unterordner
# NspLetsEncrypt\. Läuft nach jedem Commit automatisch (lokaler Git-Hook .git\hooks\post-commit).

$ErrorActionPreference = 'Stop'
$ordner = $PSScriptRoot
. (Join-Path $ordner 'NspLetsEncrypt.Common.ps1')
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

$dateien = @($NleDateien) + 'README.md', 'version.json'
$ziel = Join-Path $ordner 'NspLetsEncrypt.zip'
# Erst daneben bauen, dann ersetzen: eine halb geschriebene ZIP bleibt nie liegen
$neu = Join-Path $env:TEMP "NspLetsEncrypt-Paket-$([guid]::NewGuid().ToString('N')).zip"
# Selbst gebaut statt Compress-Archive: das speichert in PowerShell 5.1 Pfade mit "\"
$archiv = [IO.Compression.ZipFile]::Open($neu, 'Create')
try {
    foreach ($f in $dateien) {
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archiv, (Join-Path $ordner $f), "NspLetsEncrypt/$f")
    }
} finally { $archiv.Dispose() }
Move-Item $neu $ziel -Force
"NspLetsEncrypt.zip gebaut (Version $NleVersion, $($dateien.Count) Dateien)"
