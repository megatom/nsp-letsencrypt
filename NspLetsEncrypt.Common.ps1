# NspLetsEncrypt.Common.ps1
# Gemeinsame Funktionen für das Einrichtungsfenster (NspLetsEncrypt.ps1)
# und die automatische Erneuerung (NspCert-Erneuern.ps1).
# Windows PowerShell 5.1, benötigt die Module Posh-ACME und NoSpamProxy.

$NleVersion    = '2026.10.01.4'
$NleUpdateRepo = 'megatom/nsp-letsencrypt'

$NleBasis    = Join-Path $env:ProgramData 'NspLetsEncrypt'
$NleKonfig   = Join-Path $NleBasis 'config.json'
$NleLogOrdner = Join-Path $NleBasis 'logs'
$NleSkripte  = Join-Path $NleBasis 'scripts'
$NlePoshHome = Join-Path $NleBasis 'posh-acme'
$NleQuelle   = 'NspLetsEncrypt'
$NleTaskName = 'NspLetsEncrypt Erneuerung'
$NleDateien  = @('NspLetsEncrypt.Common.ps1', 'NspCert-Erneuern.ps1', 'NspCert-Anwenden.ps1', 'NspLetsEncrypt.ps1', 'Starten.cmd')
$NleZugang   = Join-Path $NleBasis 'nsp-zugang.json'
# Rechte des API-Schlüssels (NSP ab 16). Empfangskonnektoren haben kein eigenes Recht
# und laufen vermutlich über configuration; profile soll die Selbst-Verlängerung erlauben.
$NleApiRechte = @('read:configuration', 'manage:configuration',
                  'read:outboundSendConnectors', 'manage:outboundSendConnectors',
                  'read:certificates', 'read:profile', 'manage:profile')
$NleApiRechteKern = @('read:configuration', 'manage:configuration',
                      'read:outboundSendConnectors', 'manage:outboundSendConnectors')

#region Umgebung, Log, Konfiguration

function Initialize-NleUmgebung {
    # Server 2019 spricht ohne diese Zeile kein TLS 1.2 mit PowerShell-Webabfragen
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    foreach ($o in $NleBasis, $NleLogOrdner, $NleSkripte, $NlePoshHome) {
        if (-not (Test-Path $o)) { New-Item -ItemType Directory -Path $o -Force | Out-Null }
    }
    # Fenster (Admin) und Aufgabe (SYSTEM) müssen dieselben Posh-ACME-Daten sehen
    $env:POSHACME_HOME = $NlePoshHome
}

function Import-NlePoshAcme {
    Initialize-NleUmgebung
    Import-Module Posh-ACME -ErrorAction Stop -Verbose:$false
}

function Write-NleLog {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [ValidateSet('Info', 'Warnung', 'Fehler')][string]$Stufe = 'Info'
    )
    $zeile = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Stufe, $Text
    try {
        if (-not (Test-Path $NleLogOrdner)) { New-Item -ItemType Directory -Path $NleLogOrdner -Force | Out-Null }
        Add-Content -Path (Join-Path $NleLogOrdner ('{0:yyyy-MM}.log' -f (Get-Date))) -Value $zeile -Encoding UTF8
    } catch { }
    Write-Information $zeile -InformationAction Continue
}

function Write-NleEreignis {
    param(
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('Information', 'Warning', 'Error')][string]$Typ = 'Information',
        [int]$Id = 1000
    )
    try {
        if (-not [Diagnostics.EventLog]::SourceExists($NleQuelle)) {
            New-EventLog -LogName Application -Source $NleQuelle
        }
        Write-EventLog -LogName Application -Source $NleQuelle -EntryType $Typ -EventId $Id -Message $Text
    } catch {
        Write-NleLog "Ereignisprotokoll nicht beschreibbar: $($_.Exception.Message)" -Stufe Warnung
    }
}

function Get-NleKonfig {
    if (-not (Test-Path $NleKonfig)) { return $null }
    Get-Content $NleKonfig -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Save-NleKonfig {
    param([Parameter(Mandatory)]$Konfig)
    Initialize-NleUmgebung
    Set-NleOrdnerRechte
    $Konfig | ConvertTo-Json -Depth 6 | Set-Content -Path $NleKonfig -Encoding UTF8
}

function Set-NleOrdnerRechte {
    # Nur SYSTEM und Administratoren: config.json enthält die acme-dns-Zugangsdaten,
    # und die Erneuerung führt die Skripte aus diesem Ordner als SYSTEM aus.
    & icacls.exe $NleBasis /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C /Q | Out-Null
}

#endregion

#region acme-dns

function Register-NleAcmeDns {
    param([Parameter(Mandatory)][string]$Server)
    Initialize-NleUmgebung
    $Server = $Server -replace '^https?://', '' -replace '/+$', ''
    Write-NleLog "Registriere bei acme-dns ($Server) ..."
    $r = Invoke-RestMethod -Method Post -Uri "https://$Server/register" -UseBasicParsing -TimeoutSec 30
    if (-not $r.fulldomain) { throw "acme-dns hat keine Registrierung zurückgegeben." }
    Write-NleLog "Registriert: $($r.fulldomain)"
    [pscustomobject]@{
        server     = $Server
        subdomain  = $r.subdomain
        username   = $r.username
        password   = $r.password
        fulldomain = $r.fulldomain
    }
}

function Test-NleCname {
    # Prüft _acme-challenge.<host> bei öffentlichen Resolvern, weil der lokale DNS
    # oft eine interne Zone für die Maildomain hat. Let's Encrypt sieht nur das Öffentliche.
    param(
        [Parameter(Mandatory)][string]$Hostname,
        [Parameter(Mandatory)][string]$Ziel
    )
    $name = "_acme-challenge.$Hostname"
    $Ziel = $Ziel.TrimEnd('.')
    $details = foreach ($dns in @('1.1.1.1', '8.8.8.8', '')) {
        $p = @{ Name = $name; Type = 'CNAME'; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
        if ($dns) { $p.Server = $dns }
        $anzeige = if ($dns) { $dns } else { 'lokaler DNS' }
        try {
            $a = Resolve-DnsName @p | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
            $wert = if ($a) { ([string]$a.NameHost).TrimEnd('.') } else { '' }
            [pscustomobject]@{ Server = $anzeige; Oeffentlich = [bool]$dns; Erreicht = $true; Wert = $wert; Passt = ($wert -eq $Ziel) }
        } catch {
            # Name existiert nicht bzw. hat keinen CNAME: Server hat geantwortet
            $nichtDa = $_.FullyQualifiedErrorId -match 'RCODE_NAME_ERROR|NO_RECORDS|9003|9501'
            [pscustomobject]@{ Server = $anzeige; Oeffentlich = [bool]$dns; Erreicht = $nichtDa; Wert = ''; Passt = $false }
        }
    }
    $oeffentlich = @($details | Where-Object { $_.Oeffentlich -and $_.Erreicht })
    $ok = if ($oeffentlich.Count) { [bool]($oeffentlich | Where-Object Passt) } else { [bool]($details | Where-Object Passt) }
    [pscustomobject]@{ Ok = $ok; Name = $name; Ziel = $Ziel; Details = @($details) }
}

function Resolve-NleOeffentlich {
    # DNS-Abfrage bei öffentlichen Resolvern (intern gibt es oft eigene Zonen für die Maildomain).
    # Leeres Ergebnis = Server hat geantwortet, dass es den Eintrag nicht gibt.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Typ)
    $letzter = $null
    foreach ($dns in @('1.1.1.1', '8.8.8.8', '')) {
        $p = @{ Name = $Name; Type = $Typ; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
        if ($dns) { $p.Server = $dns }
        try { return @(Resolve-DnsName @p | Where-Object { "$($_.Type)" -eq $Typ }) }
        catch {
            if ($_.FullyQualifiedErrorId -match 'RCODE_NAME_ERROR|NO_RECORDS|9003|9501') { return @() }
            $letzter = $_
        }
    }
    throw $letzter
}

function Test-NleHostname {
    # Drei Stufen: Gibt es den Namen? Ist er MX der Domain? Antwortet dort ein Mailserver?
    param([Parameter(Mandatory)][string]$Hostname)
    $e = [ordered]@{
        Hostname = $Hostname; Adressen = @(); AFehler = $null
        Domain = $null; MxListe = @(); IstMx = $false; MxFehler = $null
        SmtpOk = $false; Banner = $null; SmtpFehler = $null
    }
    try { $e.Adressen = @(Resolve-NleOeffentlich $Hostname 'A' | ForEach-Object { $_.IPAddress }) }
    catch { $e.AFehler = $_.Exception.Message }

    # Domain = nächsthöhere Ebene mit MX-Einträgen (mail.firma.de -> firma.de)
    $teile = $Hostname.Split('.')
    for ($i = 1; $i -le $teile.Count - 2; $i++) {
        $kandidat = $teile[$i..($teile.Count - 1)] -join '.'
        try {
            $mx = @(Resolve-NleOeffentlich $kandidat 'MX' | Sort-Object Preference)
            if ($mx.Count) {
                $e.Domain = $kandidat
                $e.MxListe = @($mx | ForEach-Object { ([string]$_.NameExchange).TrimEnd('.').ToLower() })
                $e.IstMx = $Hostname -in $e.MxListe
                break
            }
        } catch { $e.MxFehler = $_.Exception.Message; break }
    }
    if (-not $e.Domain -and $teile.Count -ge 2) { $e.Domain = $teile[1..($teile.Count - 1)] -join '.' }

    $ip = $e.Adressen | Select-Object -First 1
    if ($ip) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $verbindung = $tcp.BeginConnect($ip, 25, $null, $null)
            if (-not $verbindung.AsyncWaitHandle.WaitOne(5000)) { throw 'keine Antwort nach 5 Sekunden' }
            $tcp.EndConnect($verbindung)
            $strom = $tcp.GetStream()
            $strom.ReadTimeout = 10000
            $leser = New-Object System.IO.StreamReader($strom)
            $zeile = $leser.ReadLine()
            if ($zeile -match '^220') { $e.SmtpOk = $true; $e.Banner = $zeile }
            else { $e.SmtpFehler = "unerwartete Antwort: $zeile" }
            try { $schreiber = New-Object System.IO.StreamWriter($strom); $schreiber.Write("QUIT`r`n"); $schreiber.Flush() } catch { }
        } catch {
            $e.SmtpFehler = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        } finally { $tcp.Close() }
    }
    [pscustomobject]$e
}

#endregion

#region NoSpamProxy

function Get-NleZugang {
    # Gespeicherter API-Schlüssel: Token mit DPAPI auf Rechner-Ebene verschlüsselt,
    # damit Fenster (Admin) und Aufgabe (SYSTEM) ihn lesen können. Ordner nur SYSTEM+Admins.
    if (-not (Test-Path $NleZugang)) { return $null }
    Get-Content $NleZugang -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Save-NleZugang {
    param([Parameter(Mandatory)]$Details, [string]$Token)
    Initialize-NleUmgebung
    Set-NleOrdnerRechte
    $alt = Get-NleZugang
    $geschuetzt = if ($Token) {
        Add-Type -AssemblyName System.Security
        [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect(
            [Text.Encoding]::UTF8.GetBytes($Token), [Text.Encoding]::UTF8.GetBytes($NleQuelle), 'LocalMachine'))
    } elseif ($alt) { $alt.Token } else { throw 'Kein Token zum Speichern.' }
    $ablauf = if ($Details.ExpirationDateUtc) { $Details.ExpirationDateUtc.UtcDateTime.ToString('o') } else { $null }
    [pscustomobject]@{
        Id        = $Details.Id
        Name      = $Details.Name
        CreatedBy = $(if ($Details.CreatedBy) { $Details.CreatedBy } elseif ($alt) { $alt.CreatedBy } else { $null })
        Ablauf    = $ablauf
        Token     = $geschuetzt
    } | ConvertTo-Json | Set-Content -Path $NleZugang -Encoding UTF8
}

function Get-NleApiToken {
    $z = Get-NleZugang
    if (-not $z -or -not $z.Token) { return $null }
    Add-Type -AssemblyName System.Security
    $klar = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect(
        [Convert]::FromBase64String($z.Token), [Text.Encoding]::UTF8.GetBytes($NleQuelle), 'LocalMachine'))
    ConvertTo-SecureString $klar -AsPlainText -Force
}

function Connect-NleNsp {
    Import-Module NoSpamProxy -ErrorAction Stop -Verbose:$false
    $token = Get-NleApiToken
    if ($token) {
        try { Connect-Nsp -ApiKey $token -IgnoreServerCertificateErrors -ErrorAction Stop | Out-Null }
        catch {
            throw "NoSpamProxy hat den API-Schlüssel abgelehnt ($($_.Exception.Message)). Im Fenster unter 'NSP-Zugang' neu anlegen."
        }
        return
    }
    # Ohne Schlüssel: Anmeldung mit dem Windows-Konto, klappt nur bis NSP 15
    try { Connect-Nsp -IgnoreServerCertificateErrors -ErrorAction Stop | Out-Null }
    catch {
        throw "Anmeldung an NoSpamProxy fehlgeschlagen ($($_.Exception.Message)). Ab NSP 16 im Fenster unter 'NSP-Zugang' einen API-Schlüssel anlegen."
    }
}

function New-NleApiSchluessel {
    param(
        [Parameter(Mandatory)][string]$Benutzer,
        [Parameter(Mandatory)][Security.SecureString]$Passwort
    )
    Import-Module NoSpamProxy -ErrorAction Stop -Verbose:$false
    $anmeldung = New-Object System.Management.Automation.PSCredential($Benutzer, $Passwort)
    Write-NleLog "Melde mich als $Benutzer an NoSpamProxy an ..."
    Connect-Nsp -Credential $anmeldung.GetNetworkCredential() -IgnoreServerCertificateErrors -ErrorAction Stop | Out-Null

    $name = "NspLetsEncrypt $env:COMPUTERNAME"
    # Ein Schlüssel darf nicht mehr als sein Konto. NSP meldet ein fehlendes Recht nur als
    # Warnung und legt dann nichts an; dieses Recht weglassen und erneut versuchen.
    $rechte = New-Object System.Collections.Generic.List[string]
    $NleApiRechte | ForEach-Object { $rechte.Add($_) }
    $neu = $null
    while ($true) {
        foreach ($alt in @(Get-NspApiKey | Where-Object { $_.Name -eq $name })) {
            Remove-NspApiKey -Id $alt.Id -ErrorAction Stop
            Write-NleLog "Alten API-Schlüssel '$name' (Id $($alt.Id)) gelöscht."
        }
        $warnungen = $null
        $fehler = ''
        try {
            $neu = New-NspApiKey -Name $name -Permissions $rechte.ToArray() -WarningVariable warnungen -WarningAction SilentlyContinue -ErrorAction Stop
        } catch { $fehler = $_.Exception.Message }
        if ($neu -and $neu.Token) { break }

        $meldung = ((@($warnungen) | ForEach-Object { "$_" }) + $fehler | Where-Object { $_ }) -join ' '
        $fehlend = @([regex]::Matches($meldung, "permission '(\w+)' on resource '(\w+)'") |
            ForEach-Object { "$($_.Groups[1].Value):$($_.Groups[2].Value)" } | Where-Object { $rechte.Contains($_) })
        if (-not $fehlend.Count) { throw "API-Schlüssel nicht angelegt: $meldung" }
        $kern = @($fehlend | Where-Object { $_ -in $NleApiRechteKern })
        if ($kern.Count) {
            throw "Das Konto $Benutzer hat in NoSpamProxy nicht das Recht $($kern -join ', '), das zum Setzen der Konnektoren nötig ist. Bitte mit einem NSP-Administrator anmelden."
        }
        foreach ($r in $fehlend) { [void]$rechte.Remove($r) }
        Write-NleLog "Konto $Benutzer hat das Recht $($fehlend -join ', ') nicht, lege den Schlüssel ohne an." -Stufe Warnung
    }
    Save-NleZugang -Details $neu -Token $neu.Token
    $ablauf = if ($neu.ExpirationDateUtc) { $neu.ExpirationDateUtc.LocalDateTime.ToString('dd.MM.yyyy') } else { 'unbegrenzt' }
    Write-NleLog "API-Schlüssel '$name' angelegt (Id $($neu.Id), gültig bis $ablauf, Rechte: $(@($neu.Permissions) -join ', '))."

    # Gegenprobe mit dem Schlüssel selbst
    $ziele = @(Get-NleZiele)
    Write-NleLog "Anmeldung mit dem API-Schlüssel klappt, $($ziele.Count) Konnektor-Stellen lesbar."
}

function Update-NleApiLaufzeit {
    # Verlängert den eigenen Schlüssel, wenn er in weniger als 60 Tagen abläuft.
    # Muss nach Connect-NleNsp laufen. Gibt eine Warnung zurück, wenn es knapp wird.
    $z = Get-NleZugang
    if (-not $z -or -not $z.Ablauf) { return $null }
    $ablauf = [DateTime]::Parse($z.Ablauf, $null, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
    $tage = [int]($ablauf - (Get-Date)).TotalDays
    if ($tage -ge 60) { return $null }
    try {
        $r = Reset-NspApiKeyLifetime -Id $z.Id -ErrorAction Stop
        Save-NleZugang -Details $r -Token $r.Token
        $neuAblauf = if ($r.ExpirationDateUtc) { $r.ExpirationDateUtc.LocalDateTime.ToString('dd.MM.yyyy') } else { 'unbegrenzt' }
        Write-NleLog "API-Schlüssel verlängert, gültig bis $neuAblauf."
        return $null
    } catch {
        Write-NleLog "API-Schlüssel konnte sich nicht selbst verlängern: $($_.Exception.Message)" -Stufe Warnung
        if ($tage -lt 30) {
            return "Der NoSpamProxy-API-Schlüssel läuft in $tage Tagen ab ($($ablauf.ToString('dd.MM.yyyy'))). " +
                   "Bitte im Fenster (Starten.cmd) unter 'NSP-Zugang' einen neuen Schlüssel anlegen."
        }
        return $null
    }
}

function Get-NleEigenschaft {
    param($Objekt, [string[]]$Namen)
    foreach ($n in $Namen) {
        $p = $Objekt.PSObject.Properties[$n]
        if ($p) { return $p.Value }
    }
    $null
}

function Get-NleEmpfangSchluessel {
    param($Konnektor)
    $id = Get-NleEigenschaft $Konnektor 'Id', 'Identity'
    if ($null -ne $id -and "$id" -ne '') { return "E|$id" }
    "E|$(Get-NleEigenschaft $Konnektor 'Name', 'DisplayName')|$(Get-NleEigenschaft $Konnektor 'Port')"
}

function Get-NleZiele {
    # Alle Stellen in NSP, die ein TLS-Zertifikat tragen können:
    # SMTP-Empfangskonnektoren und die Dispatcher der Sendekonnektoren.
    Connect-NleNsp
    $liste = New-Object System.Collections.Generic.List[object]

    foreach ($k in @(Get-NspReceiveConnector -Type Smtp)) {
        if (-not $k) { continue }
        # NSP 16: Zertifikat als Objekt in TlsCertificate (leer = keins), Thumbprint darin
        $tls = $k.PSObject.Properties['TlsCertificate']
        $tp = if ($tls) {
            if ($tls.Value) { [string]$tls.Value.Thumbprint } else { '' }
        } else {
            $tpName = @('ServerCertificateThumbprint', 'CertificateThumbprint', 'TlsCertificateThumbprint') |
                Where-Object { $k.PSObject.Properties[$_] } | Select-Object -First 1
            if ($tpName) { [string]$k.$tpName } else { $null }
        }
        $liste.Add([pscustomobject]@{
            Art             = 'Empfang'
            Schluessel      = Get-NleEmpfangSchluessel $k
            ConnectorId     = Get-NleEigenschaft $k 'Id', 'Identity'
            Name            = [string](Get-NleEigenschaft $k 'Name', 'DisplayName')
            Port            = Get-NleEigenschaft $k 'Port'
            DispatcherIndex = $null
            Dispatcher      = $null
            # $null = Eigenschaft unbekannt, nicht prüfbar
            Thumbprint      = $tp
        })
    }

    foreach ($k in @(Get-NspOutboundSendConnector)) {
        if (-not $k) { continue }
        $disp = @($k.Dispatchers)
        for ($i = 0; $i -lt $disp.Count; $i++) {
            $d = $disp[$i]
            if (-not $d -or -not $d.PSObject.Properties['TlsCertificateThumbprint']) { continue }
            # NSP 16: der Thumbprint wirkt nur mit TlsClientCertificateSelectionMode = Thumbprint
            $modus = if ($d.PSObject.Properties['TlsClientCertificateSelectionMode']) { [string]$d.TlsClientCertificateSelectionMode } else { $null }
            $tp = if ($modus -and $modus -ne 'Thumbprint') { '' } else { [string]$d.TlsCertificateThumbprint }
            $liste.Add([pscustomobject]@{
                Art             = 'Versand'
                Schluessel      = "V|$($k.Id)|$i"
                ConnectorId     = $k.Id
                Name            = [string]$k.Name
                Port            = $null
                DispatcherIndex = $i
                Dispatcher      = [string](Get-NleEigenschaft $d 'Name', 'DisplayName', 'Description')
                Thumbprint      = $tp
                Modus           = $modus
            })
        }
    }
    $liste
}

function Set-NleZertifikat {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Schluessel
    )
    if (-not $Schluessel.Count) { Write-NleLog 'Keine Konnektoren ausgewählt, nichts einzuspielen.' -Stufe Warnung; return }
    if (-not (Test-Path "Cert:\LocalMachine\My\$Thumbprint")) {
        throw "Zertifikat $Thumbprint liegt nicht im Speicher LocalMachine\My."
    }
    Connect-NleNsp

    foreach ($k in @(Get-NspReceiveConnector -Type Smtp)) {
        if (-not $k) { continue }
        if ((Get-NleEmpfangSchluessel $k) -notin $Schluessel) { continue }
        Set-NspReceiveConnector -Id $k.Id -Smtp -ServerCertificateThumbprint $Thumbprint -ErrorAction Stop
        Write-NleLog "Empfang '$(Get-NleEigenschaft $k 'Name')' (Port $(Get-NleEigenschaft $k 'Port')) -> $Thumbprint"
    }

    $versand = $Schluessel | Where-Object { $_ -like 'V|*' } | ForEach-Object {
        $t = $_.Split('|'); [pscustomobject]@{ Id = $t[1]; Index = [int]$t[2] }
    } | Group-Object Id
    foreach ($g in $versand) {
        $k = @(Get-NspOutboundSendConnector) | Where-Object { "$($_.Id)" -eq $g.Name } | Select-Object -First 1
        if (-not $k) { throw "Sendekonnektor mit Id $($g.Name) nicht gefunden." }
        $d = $k.Dispatchers
        foreach ($e in $g.Group) {
            $d[$e.Index].TlsCertificateThumbprint = $Thumbprint
            if ($d[$e.Index].PSObject.Properties['TlsClientCertificateSelectionMode']) {
                $d[$e.Index].TlsClientCertificateSelectionMode = 'Thumbprint'
            }
        }
        Set-NspOutboundSendConnector -Id $k.Id -Dispatchers $d -Smtp -ErrorAction Stop
        Write-NleLog "Versand '$($k.Name)' Dispatcher $(($g.Group.Index | ForEach-Object { $_ + 1 }) -join ', ') -> $Thumbprint"
    }

    # Gegenprobe: neu auslesen
    $nachher = @(Get-NleZiele)
    $fehlend = @($Schluessel | Where-Object { $_ -notin $nachher.Schluessel })
    if ($fehlend.Count) { throw "Konnektoren nicht mehr vorhanden: $($fehlend -join ', ')" }
    $falsch = @($nachher | Where-Object { $_.Schluessel -in $Schluessel -and $null -ne $_.Thumbprint -and $_.Thumbprint -ne $Thumbprint })
    if ($falsch.Count) {
        throw "Thumbprint nach dem Setzen nicht übernommen bei: $(($falsch | ForEach-Object { "$($_.Art) $($_.Name)" }) -join ', ')"
    }
    Write-NleLog 'NSP-Konnektoren geprüft, Thumbprint überall gesetzt.'
}

function Remove-NleAltesZertifikat {
    # Entfernt nur das Zertifikat, das dieses Werkzeug selbst vorher eingespielt hat,
    # und nur wenn NSP es nirgends mehr verwendet.
    param([string]$Alt, [string]$Neu)
    if (-not $Alt -or $Alt -eq $Neu) { return }
    $pfad = "Cert:\LocalMachine\My\$Alt"
    if (-not (Test-Path $pfad)) { return }
    $noch = @(Get-NleZiele | Where-Object { $_.Thumbprint -eq $Alt })
    if ($noch.Count) {
        Write-NleLog "Altes Zertifikat $Alt wird noch verwendet ($(($noch | ForEach-Object { "$($_.Art) $($_.Name)" }) -join ', ')) und bleibt im Speicher." -Stufe Warnung
        return
    }
    $c = Get-Item $pfad
    if ($c.Issuer -notmatch "Let's Encrypt") {
        Write-NleLog "Altes Zertifikat $Alt stammt nicht von Let's Encrypt und bleibt im Speicher." -Stufe Warnung
        return
    }
    Remove-Item $pfad -DeleteKey
    Write-NleLog "Altes Zertifikat $Alt (gültig bis $($c.NotAfter.ToString('dd.MM.yyyy'))) aus dem Speicher entfernt."
}

#endregion

#region Mail

function Send-NleMail {
    param(
        [Parameter(Mandatory)]$Konfig,
        [Parameter(Mandatory)][string]$Betreff,
        [Parameter(Mandatory)][string]$Text
    )
    $m = $Konfig.Mail
    if (-not $m -or -not $m.An) { Write-NleLog 'Keine Mail-Adresse eingetragen, Mail entfällt.' -Stufe Warnung; return }
    $client = New-Object System.Net.Mail.SmtpClient($m.Server, [int]$m.Port)
    $client.Timeout = 30000
    $nachricht = New-Object System.Net.Mail.MailMessage($m.Von, ($m.An -replace '\s*;\s*', ','), $Betreff, $Text)
    $nachricht.BodyEncoding = [Text.Encoding]::UTF8
    $nachricht.SubjectEncoding = [Text.Encoding]::UTF8
    try { $client.Send($nachricht) } finally { $nachricht.Dispose(); $client.Dispose() }
    Write-NleLog "Mail an $($m.An) gesendet: $Betreff"
}

#endregion

#region Zertifikat

function New-NleZertifikat {
    param([Parameter(Mandatory)]$Konfig, [switch]$Erzwingen)
    Import-NlePoshAcme
    $h = $Konfig.Hostname
    $reg = $Konfig.AcmeDns
    if (-not $reg -or $reg.Hostname -ne $h) { throw "Keine acme-dns-Registrierung für $h." }

    Set-PAServer $Konfig.Server
    Write-NleLog "ACME-Server: $($Konfig.Server)"
    $konto = Get-PAAccount
    if (-not $konto) {
        Write-NleLog "Lege Let's-Encrypt-Konto an ($($Konfig.Kontakt)) ..."
        $konto = New-PAAccount -Contact $Konfig.Kontakt -AcceptTOS -UseAltPluginEncryption -ErrorAction Stop
    } else {
        if (@($konto.contact) -notcontains "mailto:$($Konfig.Kontakt)") {
            Set-PAAccount -Contact $Konfig.Kontakt -ErrorAction Stop
        }
        # Zugangsdaten nicht an den Windows-Benutzer binden, sonst kann SYSTEM sie nicht lesen
        Set-PAAccount -UseAltPluginEncryption -ErrorAction Stop
    }

    $pluginArgs = @{
        ACMEServer       = $reg.server
        ACMERegistration = @{
            "_acme-challenge.$h" = @($reg.subdomain, $reg.username, $reg.password, $reg.fulldomain)
        }
    }
    Write-NleLog "Fordere Zertifikat für $h an (RSA 2048, dauert etwa 1 Minute) ..."
    try {
        $cert = New-PACertificate $h -Plugin AcmeDns -PluginArgs $pluginArgs -Install `
            -FriendlyName "NoSpamProxy $h (Let's Encrypt)" -DnsSleep 30 -Force:$Erzwingen -ErrorAction Stop
    } catch { throw (Get-NleAcmeFehlertext $_.Exception.Message) }
    if (-not $cert) {
        $cert = Get-PACertificate $h
        if ($cert) { Write-NleLog "Vorhandenes Zertifikat verwendet (noch nicht fällig, gültig bis $($cert.NotAfter.ToString('dd.MM.yyyy')))." }
    }
    if (-not $cert) { throw 'Kein Zertifikat erhalten.' }
    if (-not (Test-Path "Cert:\LocalMachine\My\$($cert.Thumbprint)")) {
        $cert | Install-PACertificate
    }
    Write-NleLog "Zertifikat $($cert.Thumbprint), gültig bis $($cert.NotAfter.ToString('dd.MM.yyyy'))"
    $cert.Thumbprint
}

function Get-NleAcmeFehlertext {
    # Typische Fehler beim Abruf in einen Hinweis übersetzen, was zu tun ist
    param([string]$Meldung)
    $hinweis = switch -Regex ($Meldung) {
        '\(401\)|Unauthorized|Nicht autorisiert' { 'acme-dns hat die Zugangsdaten abgelehnt – in Schritt 4 neu registrieren und den CNAME beim Hoster anpassen.'; break }
        'TXT record|NXDOMAIN|dns ::|DNS problem' { 'Let''s Encrypt findet den Prüfeintrag nicht – ist der CNAME beim Hoster richtig gesetzt (Schritt 4, DNS prüfen)?'; break }
        'public suffix|Invalid identifiers|rejectedIdentifier' { 'Let''s Encrypt stellt für diesen Hostnamen nichts aus – Schreibweise in Schritt 3 prüfen.'; break }
        'rateLimited|too many' { 'Let''s Encrypt bremst gerade (zu viele Versuche) – später noch einmal probieren.'; break }
        'Unable to connect|Die Verbindung|Remotename|could not be resolved|Zeitüberschreitung|timed out' { 'Keine Verbindung ins Internet (Let''s Encrypt oder acme-dns) – Firewall/Proxy prüfen.'; break }
    }
    if ($hinweis) { "$hinweis ($Meldung)" } else { $Meldung }
}

function Test-NleAblauf {
    # Spielt den kompletten Abruf gegen die Testumgebung von Let's Encrypt durch (acme-dns, CNAME,
    # Ausstellung), ohne Zertifikatspeicher und NSP anzufassen; der Testauftrag wird danach gelöscht.
    param([Parameter(Mandatory)]$Konfig)
    Import-NlePoshAcme
    $h = $Konfig.Hostname
    $reg = $Konfig.AcmeDns
    if (-not $reg -or $reg.Hostname -ne $h) { throw "Keine acme-dns-Registrierung für $h (Schritt 4)." }
    $auftrag = 'nle-ablauftest'
    try {
        Set-PAServer LE_STAGE
        if (-not (Get-PAAccount)) {
            New-PAAccount -Contact $Konfig.Kontakt -AcceptTOS -UseAltPluginEncryption -ErrorAction Stop | Out-Null
        }
        $pluginArgs = @{
            ACMEServer       = $reg.server
            ACMERegistration = @{
                "_acme-challenge.$h" = @($reg.subdomain, $reg.username, $reg.password, $reg.fulldomain)
            }
        }
        Write-NleLog "Ablauftest für $h bei der Testumgebung von Let's Encrypt (dauert etwa 1 Minute) ..."
        $cert = New-PACertificate $h -Name $auftrag -Plugin AcmeDns -PluginArgs $pluginArgs -DnsSleep 30 -Force -ErrorAction Stop
        if (-not $cert) { throw 'Let''s Encrypt hat kein Testzertifikat ausgestellt.' }
        Write-NleLog 'Testzertifikat ausgestellt (Testumgebung, nicht vertrauenswürdig, wird nicht verwendet).'
    } catch {
        throw (Get-NleAcmeFehlertext $_.Exception.Message)
    } finally {
        try { Remove-PAOrder -Name $auftrag -Force -ErrorAction Stop } catch { }
        # Für Fenster und Erneuerung wieder den echten Server einstellen
        $server = if ($Konfig.Server) { $Konfig.Server } else { 'LE_PROD' }
        try { Set-PAServer $server } catch { }
    }
}

function Install-NleErneuerung {
    param([Parameter(Mandatory)][string]$QuellOrdner)
    Initialize-NleUmgebung
    foreach ($f in $NleDateien) {
        $q = Join-Path $QuellOrdner $f
        if ((Resolve-Path $q).Path -ne (Join-Path $NleSkripte $f)) { Copy-Item $q $NleSkripte -Force }
    }
    Set-NleOrdnerRechte
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $aktion = New-ScheduledTaskAction -Execute $ps `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$(Join-Path $NleSkripte 'NspCert-Erneuern.ps1')`""
    $ausloeser = New-ScheduledTaskTrigger -Daily -At '03:17' -RandomDelay (New-TimeSpan -Hours 2)
    $konto = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $einst = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $NleTaskName -Action $aktion -Trigger $ausloeser -Principal $konto -Settings $einst `
        -Description "Erneuert das Let's-Encrypt-Zertifikat und spielt es in NoSpamProxy ein." -Force | Out-Null
    Write-NleLog "Geplante Aufgabe '$NleTaskName' eingerichtet (täglich 03:17 bis 05:17, als SYSTEM)."
}

function Invoke-NleErneuerung {
    $k = Get-NleKonfig
    if (-not $k) { throw "Keine Konfiguration unter $NleKonfig." }
    try {
        Import-NlePoshAcme
        Set-PAServer $k.Server
        Write-NleLog "Erneuerungslauf für $($k.Hostname) ($($k.Server))"
        $neu = Submit-Renewal -MainDomain $k.Hostname -ErrorAction Stop
        if ($neu) { Write-NleLog 'Zertifikat wurde erneuert.' }

        $cert = Get-PACertificate $k.Hostname
        if (-not $cert) { throw "Posh-ACME kennt kein Zertifikat für $($k.Hostname)." }
        if (-not (Test-Path "Cert:\LocalMachine\My\$($cert.Thumbprint)")) {
            $cert | Install-PACertificate
            Write-NleLog "Zertifikat $($cert.Thumbprint) in LocalMachine\My installiert."
        }

        # Auch ohne neues Zertifikat nachziehen, falls ein früherer Lauf beim
        # Einspielen scheiterte oder jemand den Konnektor von Hand geändert hat.
        $ziele = @(Get-NleZiele)
        $schluesselWarnung = Update-NleApiLaufzeit
        if ($schluesselWarnung) {
            Write-NleEreignis $schluesselWarnung -Typ Warning -Id 1004
            Send-NleMail -Konfig $k -Betreff "NoSpamProxy-API-Schlüssel läuft ab: $env:COMPUTERNAME" -Text $schluesselWarnung
        }
        $abweichend = @($ziele | Where-Object { $_.Schluessel -in @($k.Ziele) -and $null -ne $_.Thumbprint -and $_.Thumbprint -ne $cert.Thumbprint })
        if ($cert.Thumbprint -ne $k.Thumbprint -or $abweichend.Count) {
            Set-NleZertifikat -Thumbprint $cert.Thumbprint -Schluessel @($k.Ziele)
            $alt = $k.Thumbprint
            $k.Thumbprint = $cert.Thumbprint
            Save-NleKonfig $k
            Remove-NleAltesZertifikat -Alt $alt -Neu $cert.Thumbprint
            Write-NleEreignis "Neues Zertifikat $($cert.Thumbprint) für $($k.Hostname) in NoSpamProxy eingespielt, gültig bis $($cert.NotAfter.ToString('dd.MM.yyyy'))." -Id 1001
        } else {
            Write-NleLog "Nichts zu tun, gültig bis $($cert.NotAfter.ToString('dd.MM.yyyy'))."
        }

        $tage = [int]($cert.NotAfter - (Get-Date)).TotalDays
        if ($tage -lt 10) {
            $t = "Das Zertifikat für $($k.Hostname) läuft in $tage Tagen ab ($($cert.NotAfter.ToString('dd.MM.yyyy'))), wurde aber nicht erneuert."
            Write-NleLog $t -Stufe Warnung
            Write-NleEreignis $t -Typ Warning -Id 1003
            Send-NleMail -Konfig $k -Betreff "Let's Encrypt: $($k.Hostname) läuft in $tage Tagen ab" -Text $t
        }
    } catch {
        $fehler = $_
        Write-NleLog "Erneuerung fehlgeschlagen: $(Get-NleAcmeFehlertext $fehler.Exception.Message)" -Stufe Fehler
        Write-NleEreignis "Erneuerung für $($k.Hostname) fehlgeschlagen:`r`n$($fehler | Out-String)" -Typ Error -Id 1002
        try {
            $text = "Server: $env:COMPUTERNAME`r`nHost: $($k.Hostname)`r`nZeit: $(Get-Date -Format 'dd.MM.yyyy HH:mm')`r`n`r`n" +
                "$(Get-NleAcmeFehlertext $fehler.Exception.Message)`r`n`r`nDetails:`r`n$($fehler | Out-String)`r`nLog: $NleLogOrdner"
            Send-NleMail -Konfig $k -Betreff "Let's Encrypt-Erneuerung fehlgeschlagen: $($k.Hostname) ($env:COMPUTERNAME)" -Text $text
        } catch {
            Write-NleLog "Fehler-Mail konnte nicht gesendet werden: $($_.Exception.Message)" -Stufe Fehler
        }
        throw $fehler
    }
}

#endregion

#region Vorgaben für neue Server

function Get-NleNspHostname {
    # Hostname, den NoSpamProxy in seiner SMTP-Begrüßung meldet ("220 mail.firma.de - NoSpamProxy ready")
    param([string]$Server = '127.0.0.1', [int]$Port = 25)
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $verbindung = $tcp.BeginConnect($Server, $Port, $null, $null)
        if (-not $verbindung.AsyncWaitHandle.WaitOne(5000)) { return $null }
        $tcp.EndConnect($verbindung)
        $strom = $tcp.GetStream()
        $strom.ReadTimeout = 10000
        $zeile = (New-Object System.IO.StreamReader($strom)).ReadLine()
        try { $schreiber = New-Object System.IO.StreamWriter($strom); $schreiber.Write("QUIT`r`n"); $schreiber.Flush() } catch { }
        if ($zeile -match '^220[ -]([A-Za-z0-9.-]+)') {
            $h = $Matches[1].ToLower().TrimEnd('.')
            if ($h -match '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$') { return $h }
        }
        $null
    } catch { $null } finally { $tcp.Close() }
}

function Get-NleLokaleIp {
    # IPv4 der Netzwerkkarte mit Standard-Gateway; NSP lässt Mails von dort meist als Unternehmens-Mailserver zu
    $ip = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
        Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
        ForEach-Object { $_.IPv4Address.IPAddress } | Select-Object -First 1
    if ($ip) { $ip } else { 'localhost' }
}

#endregion

#region Update

function Get-NleUpdateInfo {
    # Liest version.json aus dem öffentlichen GitHub-Repo (ohne Anmeldung, mit Zeitlimit)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $url = "https://raw.githubusercontent.com/$NleUpdateRepo/main/version.json"
    $antwort = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -Headers @{ 'Cache-Control' = 'no-cache' }
    # raw.githubusercontent liefert text/plain ohne Zeichensatz, PowerShell 5.1 würde Umlaute falsch lesen
    $j = [Text.Encoding]::UTF8.GetString($antwort.RawContentStream.ToArray()) | ConvertFrom-Json
    if (-not $j.Version -or -not $j.Tag) { throw "keine gültige version.json unter $url" }
    [pscustomobject]@{
        Installiert = $NleVersion
        Version     = [string]$j.Version
        Tag         = [string]$j.Tag
        Aenderungen = @($j.Aenderungen)
        Neuer       = ([version]$j.Version -gt [version]$NleVersion)
    }
}

function Install-NleUpdate {
    # Lädt das ZIP genau dieser Version, prüft es und ersetzt die Dateien im Programmordner
    # und in der Kopie für die nächtliche Aufgabe (scripts\).
    param([Parameter(Mandatory)]$Info, [Parameter(Mandatory)][string]$Programmordner)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $arbeit = Join-Path $env:TEMP "NspLetsEncrypt-Update-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $arbeit -Force | Out-Null
    try {
        $zip = Join-Path $arbeit 'update.zip'
        $url = "https://github.com/$NleUpdateRepo/archive/refs/tags/$($Info.Tag).zip"
        Write-NleLog "Lade Version $($Info.Version) ($url) ..."
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 60
        Expand-Archive -Path $zip -DestinationPath (Join-Path $arbeit 'x') -Force
        $quelle = @(Get-ChildItem (Join-Path $arbeit 'x') -Directory)
        if ($quelle.Count -ne 1) { throw 'Unerwarteter Aufbau des Update-Pakets.' }
        $quelle = $quelle[0].FullName

        $dateien = @($NleDateien) + 'README.md', 'version.json'
        $fehlend = @($dateien | Where-Object { -not (Test-Path (Join-Path $quelle $_)) })
        if ($fehlend.Count) { throw "Im Update-Paket fehlen: $($fehlend -join ', ')" }
        $common = Get-Content (Join-Path $quelle 'NspLetsEncrypt.Common.ps1') -Raw -Encoding UTF8
        if ($common -notmatch "\`$NleVersion\s*=\s*'$([regex]::Escape($Info.Version))'") {
            throw "Das Paket enthält nicht Version $($Info.Version)."
        }
        foreach ($f in @($dateien | Where-Object { $_ -like '*.ps1' })) {
            $fehler = $null; $tok = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $quelle $f), [ref]$tok, [ref]$fehler)
            if ($fehler.Count) { throw "Fehlerhafte Datei im Update-Paket: $f" }
        }

        $ziele = @($Programmordner)
        if ((Test-Path $NleSkripte) -and ((Resolve-Path $NleSkripte).Path -ne (Resolve-Path $Programmordner).Path)) { $ziele += $NleSkripte }
        foreach ($ziel in $ziele) {
            foreach ($f in $dateien) {
                if ($ziel -eq $NleSkripte -and $f -notin $NleDateien) { continue }
                Copy-Item (Join-Path $quelle $f) (Join-Path $ziel $f) -Force
            }
            Write-NleLog "Version $($Info.Version) nach $ziel kopiert."
        }
    } finally {
        Remove-Item $arbeit -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#endregion
