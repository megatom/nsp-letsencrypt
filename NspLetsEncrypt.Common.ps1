# NspLetsEncrypt.Common.ps1
# Gemeinsame Funktionen für das Einrichtungsfenster (NspLetsEncrypt.ps1)
# und die automatische Erneuerung (NspCert-Erneuern.ps1).
# Windows PowerShell 5.1, benötigt Posh-ACME. Mit NoSpamProxy-Modul: Zertifikat für die
# NSP-Konnektoren; ohne: für den Remotedesktop-Dienst (Terminalserver).

$NleVersion    = '2026.10.02.3'
$NleUpdateRepo = 'megatom/nsp-letsencrypt'
# Wartezeit zwischen Prüfeintrag und Prüfung durch Let's Encrypt; acme-dns setzt den Eintrag sofort
$NleDnsWarten  = 10

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
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Typ, [switch]$NurOeffentlich)
    $letzter = $null
    $server = if ($NurOeffentlich) { @('1.1.1.1', '8.8.8.8') } else { @('1.1.1.1', '8.8.8.8', '') }
    foreach ($dns in $server) {
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

function Test-NleRdpHostname {
    # Terminalserver: intern muss der Name auf diesen Server zeigen, öffentlich soll er (für
    # "nur per VPN") nicht auflösbar sein, und der RDP-Dienst muss antworten
    param([Parameter(Mandatory)][string]$Hostname)
    $e = [ordered]@{
        Modus = 'RDP'; Hostname = $Hostname
        Intern = @(); InternFehler = $null; LokaleIps = @()
        Oeffentlich = @(); OeffentlichFehler = $null
        RdpOk = $false; RdpZertifikat = $null; RdpFehler = $null; Port = (Get-NleRdpPort)
    }
    $e.LokaleIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
    try {
        $e.Intern = @(Resolve-DnsName -Name $Hostname -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
            Where-Object { "$($_.Type)" -eq 'A' } | ForEach-Object { $_.IPAddress })
    } catch { $e.InternFehler = $_.Exception.Message }
    try { $e.Oeffentlich = @(Resolve-NleOeffentlich $Hostname 'A' -NurOeffentlich | ForEach-Object { $_.IPAddress }) }
    catch { $e.OeffentlichFehler = $_.Exception.Message }
    try {
        $z = Get-NleRdpTlsZertifikat
        $e.RdpOk = $true
        $e.RdpZertifikat = [pscustomobject]@{
            Name = $z.GetNameInfo('SimpleName', $false); Aussteller = $z.GetNameInfo('SimpleName', $true)
            Selbst = ($z.Subject -eq $z.Issuer); Bis = $z.NotAfter; Thumbprint = $z.Thumbprint
        }
    } catch { $e.RdpFehler = $(if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }) }
    [pscustomobject]$e
}

function Test-NleHostname {
    # Drei Stufen: Gibt es den Namen? Ist er MX der Domain? Antwortet dort ein Mailserver?
    # Ohne NoSpamProxy (Terminalserver) die RDP-Prüfung
    param([Parameter(Mandatory)][string]$Hostname)
    if (-not (Test-NleNspVorhanden)) { return Test-NleRdpHostname -Hostname $Hostname }
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
    # Alle Stellen, die ein TLS-Zertifikat tragen können: mit NSP die SMTP-Empfangskonnektoren
    # und die Dispatcher der Sendekonnektoren, ohne NSP der Remotedesktop-Dienst.
    if (-not (Test-NleNspVorhanden)) { return @(Get-NleRdpZiel) }
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
    if (-not $Schluessel.Count) { Write-NleLog 'Keine Ziele ausgewählt, nichts einzuspielen.' -Stufe Warnung; return }
    if (-not (Test-Path "Cert:\LocalMachine\My\$Thumbprint")) {
        throw "Zertifikat $Thumbprint liegt nicht im Speicher LocalMachine\My."
    }
    if ('RDP' -in $Schluessel) { Set-NleRdpZertifikat -Thumbprint $Thumbprint }
    if (-not @($Schluessel | Where-Object { $_ -ne 'RDP' }).Count) {
        $rdp = Get-NleRdpZiel
        if ($rdp.Thumbprint -ne $Thumbprint) { throw "Der RDP-Dienst hat das Zertifikat nicht übernommen (eingestellt: $($rdp.Thumbprint))." }
        try {
            $geliefert = Get-NleRdpTlsZertifikat
            if ($geliefert.Thumbprint -ne $Thumbprint) {
                throw "Der RDP-Dienst liefert noch $($geliefert.Thumbprint) aus ($($geliefert.Subject)) statt des neuen Zertifikats."
            }
            Write-NleLog 'RDP geprüft: der Dienst liefert das neue Zertifikat aus.'
        } catch {
            Write-NleLog "RDP-Gegenprobe über Port $(Get-NleRdpPort) nicht möglich: $($_.Exception.Message)" -Stufe Warnung
        }
        return
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
    Write-NleLog "Fordere Zertifikat für $h an (RSA 2048, dauert etwa eine halbe Minute) ..."
    try {
        $cert = New-PACertificate $h -Plugin AcmeDns -PluginArgs $pluginArgs -Install `
            -FriendlyName "NoSpamProxy $h (Let's Encrypt)" -DnsSleep $NleDnsWarten -Force:$Erzwingen -ErrorAction Stop
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
        '\(401\)|Unauthorized|Nicht autorisiert' { 'acme-dns hat die Zugangsdaten abgelehnt – im Abschnitt „acme-dns und CNAME“ neu registrieren und den CNAME beim Hoster anpassen.'; break }
        'TXT record|NXDOMAIN|dns ::|DNS problem' { 'Let''s Encrypt findet den Prüfeintrag nicht – ist der CNAME beim Hoster richtig gesetzt (Abschnitt „acme-dns und CNAME“, DNS prüfen)?'; break }
        'public suffix|Invalid identifiers|rejectedIdentifier' { 'Let''s Encrypt stellt für diesen Hostnamen nichts aus – Schreibweise im Abschnitt „Host“ prüfen.'; break }
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
    if (-not $reg -or $reg.Hostname -ne $h) { throw "Keine acme-dns-Registrierung für $h (Abschnitt 'acme-dns und CNAME')." }
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
        Write-NleLog "Ablauftest für $h bei der Testumgebung von Let's Encrypt (dauert etwa eine halbe Minute) ..."
        $cert = New-PACertificate $h -Name $auftrag -Plugin AcmeDns -PluginArgs $pluginArgs -DnsSleep $NleDnsWarten -Force -ErrorAction Stop
        if (-not $cert) { throw 'Let''s Encrypt hat kein Testzertifikat ausgestellt.' }
        Write-NleLog 'Testzertifikat ausgestellt (Testumgebung, nicht vertrauenswürdig, wird nicht verwendet).'
    } catch {
        throw (Get-NleAcmeFehlertext $_.Exception.Message)
    } finally {
        # Bestätigung des Testkontos verwerfen, sonst prüft der nächste Test DNS/CNAME gar nicht
        # (Let's Encrypt verwendet erfolgreiche Bestätigungen eine Weile wieder). Nur Testumgebung.
        try {
            $o = Get-PAOrder -Name $auftrag
            if ($o) { $o | Revoke-PAAuthorization -Force -ErrorAction Stop }
        } catch { }
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
        # Wartezeit steht im Auftrag; ältere Aufträge (30 s) auf den aktuellen Wert bringen
        $auftrag = Get-PAOrder -MainDomain $k.Hostname
        if ($auftrag -and $auftrag.DnsSleep -ne $NleDnsWarten) { Set-PAOrder -MainDomain $k.Hostname -DnsSleep $NleDnsWarten }
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
            Write-NleEreignis "Neues Zertifikat $($cert.Thumbprint) für $($k.Hostname) eingespielt, gültig bis $($cert.NotAfter.ToString('dd.MM.yyyy'))." -Id 1001
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

#region Remotedesktop (Betriebsart ohne NoSpamProxy)

function Test-NleNspVorhanden {
    # Schnell, ohne Get-Module -ListAvailable: liegt das NoSpamProxy-Modul in einem Modulordner?
    foreach ($p in ($env:PSModulePath -split ';' | Where-Object { $_ })) {
        if (Test-Path (Join-Path $p 'NoSpamProxy')) { return $true }
    }
    $false
}

function Get-NleRdpEinstellung {
    Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop
}

function Get-NleRdpPort {
    $p = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction SilentlyContinue).PortNumber
    if ($p) { [int]$p } else { 3389 }
}

function Get-NleRdpZiel {
    # Der RDP-Dienst als einziges Ziel auf Servern ohne NoSpamProxy
    $ts = Get-NleRdpEinstellung
    $tp = [string]$ts.SSLCertificateSHA1Hash
    if ($tp -match '^0+$') { $tp = '' }
    $c = $null
    if ($tp) {
        $c = Get-Item "Cert:\LocalMachine\My\$tp" -ErrorAction SilentlyContinue
        if (-not $c) { $c = Get-Item "Cert:\LocalMachine\Remote Desktop\$tp" -ErrorAction SilentlyContinue }
    }
    [pscustomobject]@{
        Art             = 'RDP'
        Schluessel      = 'RDP'
        ConnectorId     = $null
        Name            = 'Remotedesktop (RDP-Tcp)'
        Port            = Get-NleRdpPort
        DispatcherIndex = $null
        Dispatcher      = $null
        Thumbprint      = $tp
        Modus           = $null
        SecurityLayer   = [int]$ts.SecurityLayer
        ZertName        = $(if ($c) { $c.GetNameInfo('SimpleName', $false) } else { $null })
        ZertSelbst      = $(if ($c) { $c.Subject -eq $c.Issuer } else { $null })
        ZertBis         = $(if ($c) { $c.NotAfter } else { $null })
    }
}

function Grant-NleSchluesselLesen {
    # Der RDP-Dienst läuft als NETZWERKDIENST und braucht Leserecht auf den privaten Schlüssel,
    # sonst nimmt Windows still wieder das selbstsignierte Zertifikat
    param([Parameter(Mandatory)][string]$Thumbprint)
    $c = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction Stop
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
    if (-not $rsa) { throw "Zertifikat $Thumbprint hat keinen privaten RSA-Schlüssel." }
    $pfad = if ($rsa -is [Security.Cryptography.RSACng]) {
        Join-Path $env:ProgramData "Microsoft\Crypto\Keys\$($rsa.Key.UniqueName)"
    } else {
        Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$($rsa.CspKeyContainerInfo.UniqueKeyContainerName)"
    }
    if (-not (Test-Path $pfad)) { throw "Schlüsseldatei nicht gefunden: $pfad" }
    $acl = Get-Acl $pfad
    $netzwerkdienst = New-Object Security.Principal.SecurityIdentifier('S-1-5-20')
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($netzwerkdienst, 'Read', 'Allow')))
    Set-Acl -Path $pfad -AclObject $acl
}

function Set-NleRdpZertifikat {
    param([Parameter(Mandatory)][string]$Thumbprint)
    Grant-NleSchluesselLesen -Thumbprint $Thumbprint
    Set-CimInstance -InputObject (Get-NleRdpEinstellung) -Property @{ SSLCertificateSHA1Hash = $Thumbprint } -ErrorAction Stop
    Write-NleLog "Remotedesktop (RDP-Tcp) -> $Thumbprint"
}

function Get-NleRdpTlsZertifikat {
    # Welches Zertifikat liefert der RDP-Dienst tatsächlich aus? RDP-Aushandlung (X.224 mit Wunsch
    # TLS/CredSSP), danach TLS-Handschlag; das Zertifikat wird nur gelesen, nicht geprüft
    param([string]$Server = '127.0.0.1', [int]$Port = (Get-NleRdpPort))
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $verbindung = $tcp.BeginConnect($Server, $Port, $null, $null)
        if (-not $verbindung.AsyncWaitHandle.WaitOne(5000)) { throw "Port $Port antwortet nicht" }
        $tcp.EndConnect($verbindung)
        $strom = $tcp.GetStream()
        $strom.ReadTimeout = 10000
        $strom.WriteTimeout = 10000
        [byte[]]$anfrage = 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00
        $strom.Write($anfrage, 0, $anfrage.Length)
        $antwort = New-Object byte[] 19
        $gelesen = 0
        while ($gelesen -lt 19) {
            $n = $strom.Read($antwort, $gelesen, 19 - $gelesen)
            if ($n -le 0) { break }
            $gelesen += $n
        }
        # Byte 11: 0x02 = Antwort mit gewähltem Protokoll, 0x03 = abgelehnt (nur RDP-Sicherheitsschicht)
        if ($gelesen -lt 19 -or $antwort[11] -ne 0x02) { throw 'RDP-Dienst bietet kein TLS an (Sicherheitsschicht "RDP"?)' }
        $ssl = New-Object System.Net.Security.SslStream($strom, $false, { param($a, $b, $c, $d) $true })
        try {
            $protokolle = [Security.Authentication.SslProtocols]::Tls12 -bor [Security.Authentication.SslProtocols]::Tls11 -bor [Security.Authentication.SslProtocols]::Tls
            $ssl.AuthenticateAsClient($Server, $null, $protokolle, $false)
            New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        } finally { $ssl.Dispose() }
    } finally { $tcp.Close() }
}

function Get-NleRdpHostnameVorschlag {
    # Servername + öffentliche Domain aus dem AD: häufigste Maildomain der Benutzer, sonst das
    # erste UPN-Suffix. Interne Endungen und onmicrosoft.com zählen nicht (dafür gibt es kein Zertifikat).
    $intern = '\.(local|lan|intern|internal|corp|home|localdomain)$|onmicrosoft\.com$'
    $gueltig = '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$'
    $zaehler = @{}
    try {
        $suche = New-Object DirectoryServices.DirectorySearcher
        $suche.Filter = '(&(objectCategory=person)(objectClass=user)(mail=*))'
        $suche.PageSize = 500
        [void]$suche.PropertiesToLoad.Add('mail')
        foreach ($treffer in $suche.FindAll()) {
            $mail = [string]$treffer.Properties['mail'][0]
            if ($mail -match '@(.+)$') {
                $d = $Matches[1].ToLower().TrimEnd('.')
                if ($d -match $gueltig -and $d -notmatch $intern) { $zaehler[$d] = 1 + [int]$zaehler[$d] }
            }
        }
    } catch { }
    $domain = $null; $quelle = $null; $andere = @()
    if ($zaehler.Count) {
        $sortiert = @($zaehler.GetEnumerator() | Sort-Object Value -Descending)
        $domain = $sortiert[0].Key
        $quelle = "häufigste Domain in $($sortiert[0].Value) Mailadressen im AD"
        $andere = @($sortiert | Select-Object -Skip 1 | ForEach-Object { "$($_.Key) ($($_.Value))" })
    } else {
        try {
            $konfig = ([ADSI]'LDAP://RootDSE').configurationNamingContext
            $suffixe = @(([ADSI]"LDAP://CN=Partitions,$konfig").uPNSuffixes |
                ForEach-Object { ([string]$_).ToLower() } | Where-Object { $_ -match $gueltig -and $_ -notmatch $intern })
            if ($suffixe.Count) {
                $domain = $suffixe[0]
                $quelle = 'UPN-Suffix der Domäne'
                $andere = @($suffixe | Select-Object -Skip 1)
            }
        } catch { }
    }
    if (-not $domain) { return $null }
    [pscustomobject]@{ Hostname = "$($env:COMPUTERNAME.ToLower()).$domain"; Quelle = $quelle; Andere = $andere }
}

function Get-NleDnsServer {
    # DNS-Server dieses Servers (in der Domäne die DCs) mit Namen fürs Remoting (Kerberos braucht
    # Namen statt IP); notfalls der DC, den die Domäne selbst nennt
    $liste = New-Object System.Collections.Generic.List[object]
    $ips = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { $_.ServerAddresses } | Where-Object { $_ -and $_ -notlike '127.*' } | Select-Object -Unique)
    foreach ($ip in $ips) {
        $name = try { ([string](Resolve-DnsName -Name $ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Select-Object -First 1).NameHost).TrimEnd('.') } catch { $null }
        if ($name) { $liste.Add([pscustomobject]@{ Name = $name; Ip = $ip }) }
    }
    if (-not $liste.Count) {
        try {
            $dc = [DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().FindDomainController().Name
            $liste.Add([pscustomobject]@{ Name = $dc; Ip = $null })
        } catch { }
    }
    $liste
}

function Set-NleInterneDnsZone {
    # Legt auf dem DNS-Server (DC) per Remoting den A-Eintrag für den Hostnamen an: in einer eigenen
    # Zone nur für diesen Namen, oder in einer vorhandenen internen Zone der Domain
    param(
        [Parameter(Mandatory)][string]$Hostname,
        [Parameter(Mandatory)][string]$Ip,
        [Parameter(Mandatory)][string]$Server,
        [pscredential]$Anmeldung
    )
    $p = @{ ComputerName = $Server; ArgumentList = @($Hostname, $Ip); ErrorAction = 'Stop' }
    if ($Anmeldung) { $p.Credential = $Anmeldung }
    Invoke-Command @p -ScriptBlock {
        param($name, $ip)
        Import-Module DnsServer -ErrorAction Stop
        $zonen = @(Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsReverseLookupZone })
        $eigene = $zonen | Where-Object { $_.ZoneName -eq $name } | Select-Object -First 1
        $eltern = $zonen | Where-Object { $name.EndsWith('.' + $_.ZoneName) } |
            Sort-Object { $_.ZoneName.Length } -Descending | Select-Object -First 1
        if ($eigene) {
            $zone = $name; $eintrag = '@'
            "Zone $zone gibt es schon."
        } elseif ($eltern) {
            $zone = $eltern.ZoneName; $eintrag = $name.Substring(0, $name.Length - $zone.Length - 1)
            "Interne Zone $zone gibt es schon, der Eintrag kommt dort hinein."
        } else {
            Add-DnsServerPrimaryZone -Name $name -ReplicationScope Domain -ErrorAction Stop
            $zone = $name; $eintrag = '@'
            "Zone $zone angelegt (AD-integriert, repliziert auf alle DCs der Domäne)."
        }
        $alt = @(Get-DnsServerResourceRecord -ZoneName $zone -Name $eintrag -RRType A -ErrorAction SilentlyContinue)
        if ($alt | Where-Object { $_.RecordData.IPv4Address.IPAddressToString -eq $ip }) {
            "A-Eintrag $name -> $ip ist schon da."
        } else {
            foreach ($a in $alt) { Remove-DnsServerResourceRecord -ZoneName $zone -InputObject $a -Force -ErrorAction Stop }
            Add-DnsServerResourceRecordA -ZoneName $zone -Name $eintrag -IPv4Address $ip -ErrorAction Stop
            "A-Eintrag $name -> $ip gesetzt$(if ($alt.Count) { ' (alter Eintrag ersetzt)' })."
        }
    }
}

function Get-NleAdcsHinweise {
    # Warnungen, falls Zertifikate für RDP auch über eine interne Zertifizierungsstelle kommen könnten
    $hinweise = New-Object System.Collections.Generic.List[string]
    try {
        $konfig = ([ADSI]'LDAP://RootDSE').configurationNamingContext
        $stellen = [ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$konfig"
        $namen = @($stellen.Children | ForEach-Object { [string]$_.cn })
        if ($namen.Count) {
            $hinweise.Add("In der Domäne gibt es eine Zertifizierungsstelle ($($namen -join ', ')) – prüfen, ob RDP-Zertifikate darüber verteilt werden.")
        }
    } catch { }
    $richtlinie = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $vorlage = (Get-ItemProperty $richtlinie -Name SSLCertificateTemplateName -ErrorAction SilentlyContinue).SSLCertificateTemplateName
    if ($vorlage) {
        $hinweise.Add("Per Gruppenrichtlinie ist die RDP-Zertifikatvorlage '$vorlage' gesetzt – Windows tauscht das Zertifikat ggf. gegen eines daraus aus.")
    }
    $schicht = (Get-ItemProperty $richtlinie -Name SecurityLayer -ErrorAction SilentlyContinue).SecurityLayer
    if ($null -ne $schicht -and [int]$schicht -eq 0) {
        $hinweise.Add('Per Gruppenrichtlinie ist die RDP-Sicherheitsschicht "RDP" erzwungen – dann wird gar kein Zertifikat benutzt.')
    }
    $hinweise
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
