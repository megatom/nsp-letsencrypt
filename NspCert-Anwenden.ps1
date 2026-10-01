# NspCert-Anwenden.ps1
# Spielt ein Zertifikat von Hand in die gespeicherte Konnektor-Auswahl ein.
# Ohne -Thumbprint wird das zuletzt eingespielte Zertifikat erneut gesetzt.
#   .\NspCert-Anwenden.ps1
#   .\NspCert-Anwenden.ps1 -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567

param([string]$Thumbprint)

. (Join-Path $PSScriptRoot 'NspLetsEncrypt.Common.ps1')
$ErrorActionPreference = 'Stop'

$k = Get-NleKonfig
if (-not $k) { throw "Keine Konfiguration unter $NleKonfig." }
if (-not $Thumbprint) { $Thumbprint = $k.Thumbprint }
if (-not $Thumbprint) { throw 'Kein Thumbprint angegeben und keiner gespeichert.' }
$Thumbprint = ($Thumbprint -replace '\s', '').ToUpper()

Set-NleZertifikat -Thumbprint $Thumbprint -Schluessel @($k.Ziele)
