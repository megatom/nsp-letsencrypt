# NspCert-Erneuern.ps1
# Läuft täglich als geplante Aufgabe (SYSTEM). Erneuert das Zertifikat, wenn es fällig ist,
# spielt es in die gewählten NSP-Konnektoren ein und schickt bei Fehlern eine Mail.

. (Join-Path $PSScriptRoot 'NspLetsEncrypt.Common.ps1')
$ErrorActionPreference = 'Stop'
try {
    Invoke-NleErneuerung
    exit 0
} catch {
    exit 1
}
