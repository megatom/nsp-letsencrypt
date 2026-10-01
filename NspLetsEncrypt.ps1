# NspLetsEncrypt.ps1
# Einrichtungsfenster: Let's-Encrypt-Zertifikat per acme-dns holen, in NoSpamProxy
# einspielen und die automatische Erneuerung einrichten. Auf dem NSP-Server ausführen.

$istAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($PSVersionTable.PSEdition -eq 'Core' -or -not $istAdmin -or
    [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    # NSP-Modul und WPF brauchen Windows PowerShell 5.1 im STA-Modus, Zertifikatsspeicher braucht Adminrechte
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Start-Process $ps -Verb RunAs -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`""
    return
}

# Startzeit des Prozesses für die Zeitmessung im Log
$script:Prozessstart = (Get-Process -Id $PID).StartTime

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

function Show-Startfehler {
    # Ohne Konsole wären Fehler beim Start unsichtbar
    param([string]$Text)
    [void][System.Windows.MessageBox]::Show("Das Fenster konnte nicht starten:`n`n$Text", "NoSpamProxy – Let's Encrypt", 'OK', 'Error')
}

# Vorbelegung für neue Server (SMTP-Server: lokale IP, siehe Import-Formular)
$Vorgaben = @{
    Kontakt    = 'support.erkelenz@conbrio-group.de'
    MailAn     = 'support.erkelenz@conbrio-group.de'
    SmtpPort   = 25
    AcmeDns    = 'auth.acme-dns.io'
}

$script:Ordner = $PSScriptRoot
$script:Common = Join-Path $PSScriptRoot 'NspLetsEncrypt.Common.ps1'
if (-not (Test-Path $script:Common)) { Show-Startfehler "Datei fehlt: $script:Common"; return }
. $script:Common

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NoSpamProxy – Let's Encrypt" Width="900" Height="960" MinWidth="700" MinHeight="600"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13">
  <Window.Resources>
    <Style TargetType="GroupBox">
      <Setter Property="Margin" Value="0,0,0,10"/>
      <Setter Property="Padding" Value="8"/>
    </Style>
    <Style TargetType="Button">
      <Setter Property="Padding" Value="12,4"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="MinHeight" Value="28"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Padding" Value="3"/>
      <Setter Property="Margin" Value="0,2,8,2"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style TargetType="Label">
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
  </Window.Resources>
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="*"/>
      <RowDefinition Height="5"/>
      <RowDefinition Height="220"/>
    </Grid.RowDefinitions>
    <ScrollViewer Grid.Row="0" VerticalScrollBarVisibility="Auto">
      <StackPanel Margin="0,0,8,0">

        <GroupBox Header="Status">
          <StackPanel>
            <ProgressBar Name="prgLaden" Height="4" IsIndeterminate="True" Margin="0,0,0,6"/>
            <TextBlock Name="txtStatus" TextWrapping="Wrap" LineHeight="20"/>
            <TextBlock Name="txtUpdate" TextWrapping="Wrap" LineHeight="20"/>
            <WrapPanel Margin="0,6,0,0">
              <Button Name="btnUpdate" Content="Aktualisieren" Visibility="Collapsed" FontWeight="SemiBold"/>
              <Button Name="btnPoshInstall" Content="Posh-ACME installieren" Visibility="Collapsed"/>
              <Button Name="btnWacsAus" Content="win-acme-Aufgabe deaktivieren" Visibility="Collapsed"/>
            </WrapPanel>
          </StackPanel>
        </GroupBox>

        <GroupBox Header="1. NSP-Zugang (ab NoSpamProxy 16)">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="175"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/>
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Grid.ColumnSpan="2" TextWrapping="Wrap" Foreground="#666" Margin="0,0,0,6"
                       Text="Einmalig mit einem NSP-Administrator anmelden. Das Werkzeug legt damit einen API-Schlüssel an und speichert nur diesen, nicht das Passwort."/>
            <Label Grid.Row="1" Content="Benutzer"/>
            <TextBox Grid.Row="1" Grid.Column="1" Name="txtNspBenutzer" ToolTip="z. B. Administrator oder DOMAENE\Administrator"/>
            <Label Grid.Row="2" Content="Passwort"/>
            <PasswordBox Grid.Row="2" Grid.Column="1" Name="pwdNspPasswort" Padding="3" Margin="0,2,8,2" VerticalContentAlignment="Center"/>
            <DockPanel Grid.Row="3" Grid.Column="1" Margin="0,6,0,0">
              <Button DockPanel.Dock="Left" Name="btnApiKey" Content="API-Schlüssel anlegen"/>
              <TextBlock Name="txtApiStatus" VerticalAlignment="Center" TextWrapping="Wrap"/>
            </DockPanel>
          </Grid>
        </GroupBox>

        <GroupBox Header="2. NoSpamProxy-Konnektoren">
          <StackPanel>
            <StackPanel Orientation="Horizontal">
              <Button Name="btnKonnektoren" Content="Konnektoren laden"/>
              <TextBlock VerticalAlignment="Center" Foreground="#666"
                         Text="Angehakte Stellen bekommen das Zertifikat, auch bei jeder Erneuerung."/>
            </StackPanel>
            <StackPanel Name="pnlZiele" Margin="0,8,0,0"/>
            <TextBlock Name="txtZieleStatus" Margin="0,6,0,0" TextWrapping="Wrap"/>
          </StackPanel>
        </GroupBox>

        <GroupBox Header="3. Host">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="175"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/>
            </Grid.RowDefinitions>
            <Label Grid.Row="0" Content="Hostname"/>
            <TextBox Grid.Row="0" Grid.Column="1" Name="txtHost" ToolTip="z. B. mail.firma.de"/>
            <Button Grid.Row="0" Grid.Column="2" Name="btnHostPruefen" Content="Prüfen" Margin="0,2,0,2"
                    ToolTip="Prüft, ob es den Namen gibt, ob er Mailserver der Domain ist und ob dort ein Mailserver antwortet"/>
            <TextBlock Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="2" Name="txtHostPruefung" Margin="0,2,0,6" TextWrapping="Wrap" LineHeight="20"/>
            <Label Grid.Row="2" Content="Kontakt-Mail (LE)"/>
            <TextBox Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="2" Name="txtKontakt" ToolTip="Let's Encrypt schickt hierhin Ablauf-Hinweise"/>
            <TextBlock Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="2" Name="txtHostStatus" Margin="0,6,0,0" TextWrapping="Wrap"/>
          </Grid>
        </GroupBox>

        <GroupBox Header="4. acme-dns und CNAME">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="175"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/>
            </Grid.RowDefinitions>
            <Label Grid.Row="0" Content="acme-dns-Server"/>
            <TextBox Grid.Row="0" Grid.Column="1" Name="txtAcmeServer"/>
            <Button Grid.Row="0" Grid.Column="2" Name="btnRegistrieren" Content="Registrieren" Margin="0,2,0,2"/>
            <Label Grid.Row="1" Content="CNAME (voll)"/>
            <TextBox Grid.Row="1" Grid.Column="1" Name="txtCnameName" IsReadOnly="True"/>
            <Button Grid.Row="1" Grid.Column="2" Name="btnKopName" Content="Kopieren" Margin="0,2,0,2"/>
            <Label Grid.Row="2" Content="DNS-Eintrag beim Hoster"/>
            <TextBox Grid.Row="2" Grid.Column="1" Name="txtCnameKurz" IsReadOnly="True"
                     ToolTip="Name des Eintrags ohne die Domain selbst (so erwarten es die meisten Hoster, z. B. IONOS)"/>
            <Button Grid.Row="2" Grid.Column="2" Name="btnKopKurz" Content="Kopieren" Margin="0,2,0,2"/>
            <Label Grid.Row="3" Content="zeigt auf"/>
            <TextBox Grid.Row="3" Grid.Column="1" Name="txtCnameZiel" IsReadOnly="True"/>
            <Button Grid.Row="3" Grid.Column="2" Name="btnKopZiel" Content="Kopieren" Margin="0,2,0,2"/>
            <DockPanel Grid.Row="4" Grid.Column="1" Grid.ColumnSpan="2" Margin="0,6,0,0">
              <Button DockPanel.Dock="Left" Name="btnDnsPruefen" Content="DNS prüfen"/>
              <TextBlock Name="txtDnsStatus" VerticalAlignment="Center" TextWrapping="Wrap"/>
            </DockPanel>
          </Grid>
        </GroupBox>

        <GroupBox Header="5. Mail bei Fehlern">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="175"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="80"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/>
            </Grid.RowDefinitions>
            <Label Grid.Row="0" Content="An"/>
            <TextBox Grid.Row="0" Grid.Column="1" Grid.ColumnSpan="3" Name="txtMailAn" ToolTip="Mehrere Adressen mit ; trennen"/>
            <Label Grid.Row="1" Content="Absender"/>
            <TextBox Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="3" Name="txtMailVon"/>
            <Label Grid.Row="2" Content="SMTP-Server"/>
            <TextBox Grid.Row="2" Grid.Column="1" Name="txtSmtp"/>
            <Label Grid.Row="2" Grid.Column="2" Content="Port"/>
            <TextBox Grid.Row="2" Grid.Column="3" Name="txtPort"/>
            <DockPanel Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="3" Margin="0,6,0,0">
              <Button DockPanel.Dock="Left" Name="btnTestmail" Content="Testmail senden"/>
              <TextBlock Name="txtMailStatus" VerticalAlignment="Center" TextWrapping="Wrap"/>
            </DockPanel>
          </Grid>
        </GroupBox>

        <GroupBox Header="6. Zertifikat">
          <StackPanel>
            <TextBlock Name="txtZertHinweis" TextWrapping="Wrap" Margin="0,0,0,8"/>
            <CheckBox Name="chkErzwingen" Margin="0,0,0,8"
                      Content="Neu ausstellen, auch wenn das vorhandene Zertifikat noch nicht fällig ist"/>
            <WrapPanel>
              <Button Name="btnAblaufTest" Content="Ablauf testen"
                      ToolTip="Spielt den Abruf bei der Testumgebung von Let's Encrypt komplett durch (acme-dns, CNAME, Ausstellung) und prüft den NSP-Zugang – ohne echtes Zertifikat, ohne etwas zu ändern."/>
              <Button Name="btnAusstellen" Content="Zertifikat holen, einspielen und Erneuerung einrichten" FontWeight="SemiBold"/>
              <Button Name="btnErneuernJetzt" Content="Erneuerung testen (optional)"
                      ToolTip="Führt die nächtliche Prüfung sofort als SYSTEM aus. Nur zum Kontrollieren, nötig ist es nicht."/>
            </WrapPanel>
            <TextBlock Name="txtAblaufStatus" TextWrapping="Wrap" Margin="0,8,0,0" LineHeight="20"/>
            <TextBlock Name="txtZertStatus" TextWrapping="Wrap" Margin="0,8,0,0"/>
          </StackPanel>
        </GroupBox>

      </StackPanel>
    </ScrollViewer>
    <GridSplitter Grid.Row="1" HorizontalAlignment="Stretch" Background="#DDD"/>
    <TextBox Grid.Row="2" Name="txtLog" IsReadOnly="True" FontFamily="Consolas" FontSize="12"
             TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" VerticalContentAlignment="Top" Margin="0"/>
  </Grid>
</Window>
'@

try { $fenster = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml)) }
catch { Show-Startfehler $_.Exception.Message; return }
# Nie höher als der sichtbare Bildschirm (RDP-Sitzungen sind oft niedrig), sonst liegen Titelleiste oder Log außerhalb
$arbeitsflaeche = [System.Windows.SystemParameters]::WorkArea
if ($fenster.Height -gt $arbeitsflaeche.Height) { $fenster.Height = $arbeitsflaeche.Height }
$ui = @{}
foreach ($n in $xaml.SelectNodes("//*[@Name]")) {
    $name = $n.GetAttribute('Name')
    $ui[$name] = $fenster.FindName($name)
}
$fenster.Title = "NoSpamProxy – Let's Encrypt (Version $NleVersion)"
$script:Knoepfe = 'btnAblaufTest', 'btnUpdate', 'btnPoshInstall', 'btnWacsAus', 'btnRegistrieren', 'btnDnsPruefen', 'btnApiKey', 'btnKonnektoren',
                  'btnTestmail', 'btnAusstellen', 'btnErneuernJetzt'
$script:AcmeDns = $null
$script:DnsOk = $false
$script:ZieleGeladen = $false
$script:GespeicherteZiele = @()
$script:Aufgabe = $null

#region Hilfsfunktionen

function Add-Log {
    param([AllowEmptyString()][string]$Text)
    $ui.txtLog.AppendText("$Text`r`n")
    $ui.txtLog.ScrollToEnd()
}

$script:Farben = @{ ok = '#1B7F3B'; fehler = '#B00020'; warnung = '#B35C00'; hinweis = '#666666' }

function Set-Meldung {
    param($Feld, [AllowEmptyString()][string]$Text, [ValidateSet('ok', 'fehler', 'warnung', 'hinweis')][string]$Art = 'hinweis')
    $Feld.Text = $Text
    $Feld.Foreground = $script:Farben[$Art]
}

function Set-Zeilen {
    # Mehrere Zeilen, jede nach ihrem ersten Zeichen gefärbt (✔ ✘ ⚠, sonst grau)
    param($Feld, [string[]]$Zeilen)
    $Feld.Inlines.Clear()
    foreach ($z in $Zeilen) {
        if ($Feld.Inlines.Count) { $Feld.Inlines.Add((New-Object System.Windows.Documents.LineBreak)) }
        $lauf = New-Object System.Windows.Documents.Run($z)
        $art = switch ($z.Substring(0, 1)) { '✔' { 'ok' } '✘' { 'fehler' } '⚠' { 'warnung' } default { 'hinweis' } }
        $lauf.Foreground = $script:Farben[$art]
        $Feld.Inlines.Add($lauf)
    }
}

function Show-Frage {
    param([string]$Text)
    [System.Windows.MessageBox]::Show($fenster, $Text, "NoSpamProxy – Let's Encrypt", 'YesNo', 'Question') -eq 'Yes'
}

function Set-Beschaeftigt {
    param([bool]$An)
    foreach ($k in $script:Knoepfe) { $ui[$k].IsEnabled = -not $An }
    $fenster.Cursor = if ($An) { [System.Windows.Input.Cursors]::Wait } else { $null }
}

# Längere Schritte laufen in einem eigenen Runspace, damit das Fenster nicht einfriert.
# Ausgaben (Write-NleLog, Warnungen, Verbose) erscheinen laufend im Log unten.
$script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$script:Timer.Interval = [TimeSpan]::FromMilliseconds(400)
$script:Timer.Add_Tick({ Update-Hintergrund })

function Start-Hintergrund {
    # -Fehler: eigene Fehlerbehandlung statt Meldungsfenster (z. B. für die Prüfungen beim Start)
    param([scriptblock]$Arbeit, [object[]]$Argumente = @(), [scriptblock]$Danach, [scriptblock]$Fehler)
    if ($script:Aufgabe) { return }
    Set-Beschaeftigt $true
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript(". '$($script:Common.Replace("'", "''"))'; `$ErrorActionPreference = 'Stop'")
    [void]$ps.Invoke()
    $ps.Commands.Clear()
    [void]$ps.AddScript($Arbeit.ToString())
    foreach ($a in $Argumente) { [void]$ps.AddArgument($a) }
    $script:Aufgabe = @{ PS = $ps; RS = $rs; Handle = $ps.BeginInvoke(); Danach = $Danach; Fehler = $Fehler; I = 0; W = 0; V = 0; E = 0 }
    $script:Timer.Start()
}

function Write-HintergrundAusgabe {
    $a = $script:Aufgabe
    $s = $a.PS.Streams
    while ($a.I -lt $s.Information.Count) { Add-Log ([string]$s.Information[$a.I].MessageData); $a.I++ }
    while ($a.W -lt $s.Warning.Count) { Add-Log ('WARNUNG: ' + $s.Warning[$a.W].Message); $a.W++ }
    while ($a.V -lt $s.Verbose.Count) { Add-Log ('    ' + $s.Verbose[$a.V].Message); $a.V++ }
    while ($a.E -lt $s.Error.Count) { Add-Log ('FEHLER: ' + $s.Error[$a.E].ToString()); $a.E++ }
}

function Update-Hintergrund {
    $a = $script:Aufgabe
    if (-not $a) { $script:Timer.Stop(); return }
    Write-HintergrundAusgabe
    if (-not $a.Handle.IsCompleted) { return }
    $script:Timer.Stop()
    $ergebnis = $null
    $fehler = $null
    try { $ergebnis = $a.PS.EndInvoke($a.Handle) }
    catch {
        $fehler = $_.Exception
        while ($fehler.InnerException) { $fehler = $fehler.InnerException }
    }
    Write-HintergrundAusgabe
    $a.PS.Dispose()
    $a.RS.Dispose()
    $script:Aufgabe = $null
    Set-Beschaeftigt $false
    if ($fehler) {
        Add-Log "FEHLER: $($fehler.Message)"
        if ($a.Fehler) { & $a.Fehler $fehler.Message }
        else { [void][System.Windows.MessageBox]::Show($fenster, $fehler.Message, 'Fehler', 'OK', 'Error') }
        return
    }
    if ($a.Danach) { & $a.Danach @($ergebnis) }
}

function Update-Status {
    $zeilen = New-Object System.Collections.Generic.List[string]
    $c = $null; $task = $null; $info = $null
    $f = $script:Fakten
    if (-not $f) {
        $zeilen.Add('–  Prüfe Module (NoSpamProxy, Posh-ACME) ...')
    } else {
        if ($f.Nsp) { $zeilen.Add("✔  NoSpamProxy-Modul $($f.Nsp)") }
        else { $zeilen.Add('✘  NoSpamProxy-Modul fehlt – das Werkzeug muss auf dem NSP-Server laufen.') }
        if ($f.Posh) { $zeilen.Add("✔  Posh-ACME $($f.Posh)") }
        else { $zeilen.Add('✘  Posh-ACME fehlt') }
    }
    $ui.btnPoshInstall.Visibility = if ($f -and -not $f.Posh) { 'Visible' } else { 'Collapsed' }

    $k = Get-NleKonfig
    if ($k -and $k.Thumbprint) {
        $c = Get-Item "Cert:\LocalMachine\My\$($k.Thumbprint)" -ErrorAction SilentlyContinue
        if ($c) {
            $stage = if ($c.Issuer -match 'STAGING') { ' (Staging)' } else { '' }
            $zeilen.Add("✔  Zertifikat $($k.Hostname)$stage gültig bis $($c.NotAfter.ToString('dd.MM.yyyy')), $($k.Thumbprint)")
        } else {
            $zeilen.Add("✘  Gespeichertes Zertifikat $($k.Thumbprint) fehlt im Speicher")
        }
    }

    $z = Get-NleZugang
    if ($z) {
        $ablauf = if ($z.Ablauf) { [DateTime]::Parse($z.Ablauf, $null, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().ToString('dd.MM.yyyy') } else { 'unbegrenzt' }
        $wer = if ($z.CreatedBy) { ", angelegt von $($z.CreatedBy)" } else { '' }
        $zeilen.Add("✔  NSP-API-Schlüssel '$($z.Name)' gültig bis $ablauf$wer")
        Set-Meldung $ui.txtApiStatus "✔ Schlüssel vorhanden, gültig bis $ablauf." ok
    } else {
        $zeilen.Add('–  Kein NSP-API-Schlüssel (ab NSP 16 nötig, Schritt 1)')
        Set-Meldung $ui.txtApiStatus 'Noch kein Schlüssel, bitte anlegen.' hinweis
    }

    $task = Get-ScheduledTask -TaskName $NleTaskName -ErrorAction SilentlyContinue
    if ($task) {
        $info = $task | Get-ScheduledTaskInfo
        $gelaufen = $info.LastRunTime -and $info.LastRunTime.Year -gt 2000
        $lauf = if ($gelaufen) {
            "letzter Lauf $($info.LastRunTime.ToString('dd.MM.yyyy HH:mm')), Ergebnis $($info.LastTaskResult)"
        } else { 'noch nicht gelaufen' }
        $zeichen = if ($gelaufen -and $info.LastTaskResult -ne 0) { '⚠' } else { '✔' }
        $zeilen.Add("$zeichen  Erneuerung eingerichtet ($($task.State)), $lauf")
    } else {
        $zeilen.Add('–  Erneuerung noch nicht eingerichtet')
    }

    $wacs = if ($f) { @($f.Wacs | Where-Object { $_ }) } else { @() }
    if (-not $f) {
        $zeilen.Add('–  Prüfe geplante Aufgaben (win-acme) ...')
        $ui.btnWacsAus.Visibility = 'Collapsed'
    } elseif ($wacs.Count) {
        $zeilen.Add("⚠  win-acme-Aufgabe aktiv ($($wacs -join ', ')) – erneuert weiter und überschreibt den Empfangskonnektor.")
        $ui.btnWacsAus.Visibility = 'Visible'
    } else {
        $ui.btnWacsAus.Visibility = 'Collapsed'
    }
    Set-Zeilen $ui.txtStatus $zeilen

    # Schritt 6: was zu tun ist und ob die Erneuerung läuft
    if ($k -and $k.Thumbprint -and $c -and $task) {
        Set-Meldung $ui.txtZertHinweis ('Ist eingerichtet, die Erneuerung läuft jede Nacht automatisch – hier ist nichts mehr zu tun. ' +
            'Den großen Knopf nur erneut drücken, wenn du oben Konnektoren oder Hostname geändert hast.') hinweis
        $gelaufen = $info.LastRunTime -and $info.LastRunTime.Year -gt 2000
        if (-not $gelaufen) {
            Set-Meldung $ui.txtZertStatus "✔ Zertifikat gültig bis $($c.NotAfter.ToString('dd.MM.yyyy')), automatische Erneuerung aktiv (erster Lauf heute Nacht)." ok
        } elseif ($info.LastTaskResult -eq 0) {
            Set-Meldung $ui.txtZertStatus "✔ Zertifikat gültig bis $($c.NotAfter.ToString('dd.MM.yyyy')), automatische Erneuerung aktiv, letzter Lauf $($info.LastRunTime.ToString('dd.MM.yyyy HH:mm')) erfolgreich." ok
        } else {
            Set-Meldung $ui.txtZertStatus "⚠ Zertifikat gültig bis $($c.NotAfter.ToString('dd.MM.yyyy')), aber der letzte Lauf $($info.LastRunTime.ToString('dd.MM.yyyy HH:mm')) ist fehlgeschlagen (Ergebnis $($info.LastTaskResult)) – siehe Log." warnung
        }
    } else {
        Set-Meldung $ui.txtZertHinweis ("Holt das Zertifikat bei Let's Encrypt, spielt es in die angehakten Konnektoren ein und richtet " +
            'die tägliche automatische Erneuerung ein. Vorher die Schritte 1 bis 5 erledigen. Mit „Ablauf testen“ lässt sich ' +
            'vorher alles prüfen, ohne ein echtes Zertifikat zu holen.') hinweis
        Set-Meldung $ui.txtZertStatus '' hinweis
    }
    Update-HostStatus
}

function Update-HostStatus {
    $k = Get-NleKonfig
    $h = $ui.txtHost.Text.Trim().ToLower().TrimEnd('.')
    if (-not $h) { Set-Meldung $ui.txtHostStatus 'Hostname eintragen, z. B. mail.firma.de.' hinweis; return }
    if ($k -and $k.Thumbprint) {
        # Staging lässt sich nur noch von Hand in config.json setzen
        $stage = if ($k.Server -eq 'LE_STAGE') { ' (Staging laut config.json)' } else { '' }
        if ($k.Hostname -eq $h -and $k.Kontakt -eq $ui.txtKontakt.Text.Trim()) {
            Set-Meldung $ui.txtHostStatus "✔ Eingerichtet: $h$stage" ok
        } else {
            Set-Meldung $ui.txtHostStatus "⚠ Geändert – wird erst mit Schritt 6 übernommen (eingerichtet ist $($k.Hostname))." warnung
        }
    } else {
        Set-Meldung $ui.txtHostStatus 'Wird mit Schritt 6 übernommen.' hinweis
    }
}

# Hostname-Prüfung läuft neben allem anderen her und sperrt keine Knöpfe,
# sonst ginge ein Klick direkt nach dem Verlassen des Feldes verloren.
$script:HostPruefung = $null
$script:HostGeprueft = $null
$script:HostTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:HostTimer.Interval = [TimeSpan]::FromMilliseconds(300)
$script:HostTimer.Add_Tick({ Update-HostPruefung })

function Start-HostPruefung {
    param([switch]$Immer)
    $h = $ui.txtHost.Text.Trim().ToLower().TrimEnd('.')
    if ($h -notmatch '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$') {
        if ($h) { Set-Zeilen $ui.txtHostPruefung @('✘  Kein gültiger Hostname, z. B. mail.firma.de') }
        else { $ui.txtHostPruefung.Inlines.Clear() }
        $script:HostGeprueft = $null
        return
    }
    if ($script:HostPruefung -or (-not $Immer -and $script:HostGeprueft -eq $h)) { return }
    $script:HostGeprueft = $h
    Set-Zeilen $ui.txtHostPruefung @("–  Prüfe $h ...")
    $ui.btnHostPruefen.IsEnabled = $false
    $ps = [powershell]::Create()
    [void]$ps.AddScript(". '$($script:Common.Replace("'", "''"))'; Test-NleHostname -Hostname '$h'")
    $script:HostPruefung = @{ PS = $ps; Handle = $ps.BeginInvoke(); Name = $h }
    $script:HostTimer.Start()
}

function Update-HostPruefung {
    $p = $script:HostPruefung
    if (-not $p) { $script:HostTimer.Stop(); return }
    if (-not $p.Handle.IsCompleted) { return }
    $script:HostTimer.Stop()
    $script:HostPruefung = $null
    $ui.btnHostPruefen.IsEnabled = $true
    $r = $null
    $fehler = $null
    try { $r = @($p.PS.EndInvoke($p.Handle))[-1] }
    catch { $fehler = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message } }
    $p.PS.Dispose()
    $h = $ui.txtHost.Text.Trim().ToLower().TrimEnd('.')
    if ($p.Name -ne $h) { Start-HostPruefung; return }
    if (-not $r) { Set-Zeilen $ui.txtHostPruefung @("⚠  Prüfung fehlgeschlagen: $fehler"); return }

    $z = New-Object System.Collections.Generic.List[string]
    if ($r.AFehler) { $z.Add("⚠  Namensauflösung fehlgeschlagen: $($r.AFehler)") }
    elseif (-not @($r.Adressen).Count) { $z.Add("✘  $($r.Hostname) gibt es im öffentlichen DNS nicht – Tippfehler?") }
    else { $z.Add("✔  $($r.Hostname) → $(@($r.Adressen) -join ', ')") }

    if ($r.MxFehler) { $z.Add("⚠  MX-Abfrage fehlgeschlagen: $($r.MxFehler)") }
    elseif ($r.IstMx) { $z.Add("✔  ist Mailserver (MX) für $($r.Domain)") }
    elseif (@($r.MxListe).Count) { $z.Add("⚠  nicht als Mailserver (MX) für $($r.Domain) eingetragen, dort steht: $(@($r.MxListe) -join ', ')") }
    else { $z.Add("⚠  $($r.Domain) hat keinen MX-Eintrag") }

    if (@($r.Adressen).Count) {
        if ($r.SmtpOk) {
            $banner = if ($r.Banner.Length -gt 90) { $r.Banner.Substring(0, 90) + ' …' } else { $r.Banner }
            $z.Add("✔  Mailserver antwortet: $banner")
        } else {
            $z.Add("⚠  Port 25 von hier aus nicht erreichbar ($($r.SmtpFehler)) – von innen oft normal, von außen kann es trotzdem gehen.")
        }
    }
    Set-Zeilen $ui.txtHostPruefung $z
    Add-Log "Hostname-Prüfung $($r.Hostname):"
    foreach ($zeile in $z) { Add-Log "    $zeile" }
}

function Show-Cname {
    $r = $script:AcmeDns
    if (-not $r) {
        $ui.txtCnameName.Text = ''; $ui.txtCnameKurz.Text = ''; $ui.txtCnameZiel.Text = ''
        Set-Meldung $ui.txtDnsStatus ('Zuerst auf „Registrieren“ klicken – danach erscheinen hier die Werte für den ' +
            'DNS-Eintrag beim Hoster. Erst dann kann DNS geprüft werden.') hinweis
        return
    }
    $teile = $r.Hostname.Split('.')
    $ui.txtCnameName.Text = "_acme-challenge.$($r.Hostname)"
    $ui.txtCnameKurz.Text = if ($teile.Count -gt 2) { '_acme-challenge.' + ($teile[0..($teile.Count - 3)] -join '.') } else { '_acme-challenge' }
    $ui.txtCnameZiel.Text = $r.fulldomain
    $h = $ui.txtHost.Text.Trim().ToLower().TrimEnd('.')
    if ($h -and $h -ne $r.Hostname) {
        Set-Meldung $ui.txtDnsStatus "Registrierung gehört zu $($r.Hostname) – für $h neu registrieren." fehler
    }
}

function Update-ZieleStatus {
    $ziele = @($script:Ziele)
    if (-not $ziele.Count) { Set-Meldung $ui.txtZieleStatus '✘ Keine Konnektoren gefunden.' fehler; return }
    $k = Get-NleKonfig
    $aktuell = if ($k) { $k.Thumbprint } else { $null }
    $gewaehlt = @(Get-GewaehlteZiele)
    $text = "$($ziele.Count) Stellen gelesen, $($gewaehlt.Count) ausgewählt"
    if (-not $gewaehlt.Count) { Set-Meldung $ui.txtZieleStatus "⚠ $text – ohne Häkchen bekommt kein Konnektor das Zertifikat." warnung; return }
    if (-not $aktuell) { Set-Meldung $ui.txtZieleStatus "✔ $text." ok; return }
    $ohne = @($ziele | Where-Object { $_.Schluessel -in $gewaehlt -and $_.Thumbprint -ne $aktuell })
    if ($ohne.Count) {
        Set-Meldung $ui.txtZieleStatus "⚠ $text – $($ohne.Count) davon tragen noch nicht das Zertifikat dieses Werkzeugs (wird mit Schritt 6 oder heute Nacht gesetzt)." warnung
    } else {
        Set-Meldung $ui.txtZieleStatus "✔ $text – alle tragen das Zertifikat dieses Werkzeugs." ok
    }
}

function Show-Ziele {
    param($Ziele)
    $script:Ziele = @($Ziele)
    $ui.pnlZiele.Children.Clear()
    $script:ZieleGeladen = $true
    $k = Get-NleKonfig
    $aktuell = if ($k) { $k.Thumbprint } else { $null }
    $vorbelegen = -not @($script:GespeicherteZiele).Count
    $sendeIds = @($Ziele | Where-Object Art -eq 'Versand' | ForEach-Object { "$($_.ConnectorId)" } | Select-Object -Unique)
    foreach ($z in $Ziele) {
        if ($z.Art -eq 'Empfang') {
            $text = "Empfang:  $($z.Name)  (Port $($z.Port))"
            $vor = "$($z.Port)" -eq '25'
        } else {
            $zusatz = if ($z.Dispatcher) { " ($($z.Dispatcher))" } else { '' }
            $text = "Versand:  $($z.Name), Dispatcher $($z.DispatcherIndex + 1)$zusatz"
            $vor = ($z.Name -match 'Default|Standard') -or $sendeIds.Count -eq 1
        }
        $tp = if ($null -eq $z.Thumbprint) { 'nicht auslesbar' }
              elseif (-not $z.Thumbprint -and $z.Modus -and $z.Modus -ne 'Thumbprint') { "keins (Modus $($z.Modus))" }
              elseif (-not $z.Thumbprint) { 'keins' }
              elseif ($z.Thumbprint -eq $aktuell) { "$($z.Thumbprint) (dieses Werkzeug)" }
              else { $z.Thumbprint }
        $cb = New-Object System.Windows.Controls.CheckBox
        $inhalt = New-Object System.Windows.Controls.TextBlock
        $inhalt.Text = "$text     –  aktuell: $tp"
        $inhalt.TextWrapping = 'Wrap'
        $cb.Content = $inhalt
        $cb.Tag = $z.Schluessel
        $cb.Margin = '0,3,0,3'
        $cb.IsChecked = if ($vorbelegen) { $vor } else { $z.Schluessel -in $script:GespeicherteZiele }
        $cb.Add_Click({ Update-ZieleStatus })
        [void]$ui.pnlZiele.Children.Add($cb)
    }
    if (-not @($Ziele).Count) {
        $t = New-Object System.Windows.Controls.TextBlock
        $t.Text = 'Keine Konnektoren gefunden.'
        [void]$ui.pnlZiele.Children.Add($t)
    }
    $fremd = @($script:GespeicherteZiele | Where-Object { $_ -notin @($Ziele.Schluessel) })
    if ($fremd.Count) { Add-Log "WARNUNG: Gespeicherte Konnektoren nicht mehr vorhanden: $($fremd -join ', ')" }
    Update-ZieleStatus
}

function Get-GewaehlteZiele {
    @($ui.pnlZiele.Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] -and $_.IsChecked } |
        ForEach-Object { [string]$_.Tag })
}

function Read-Formular {
    param([switch]$Vollstaendig)
    $h = $ui.txtHost.Text.Trim().ToLower().TrimEnd('.')
    if ($h -notmatch '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$') {
        Add-Log 'Bitte einen gültigen Hostnamen eintragen, z. B. mail.firma.de.'
        return $null
    }
    $kontakt = $ui.txtKontakt.Text.Trim()
    if ($Vollstaendig -and $kontakt -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        Add-Log 'Bitte eine gültige Kontakt-Mail eintragen.'
        return $null
    }
    $port = 0
    if (-not [int]::TryParse($ui.txtPort.Text.Trim(), [ref]$port)) { $port = 25 }
    $alt = Get-NleKonfig
    $mailAn = $ui.txtMailAn.Text.Trim(); $mailVon = $ui.txtMailVon.Text.Trim(); $mailServer = $ui.txtSmtp.Text.Trim()
    $getestet = if ($alt -and $alt.Mail -and $alt.Mail.PSObject.Properties['Getestet'] -and $alt.Mail.An -eq $mailAn -and
                    $alt.Mail.Von -eq $mailVon -and $alt.Mail.Server -eq $mailServer -and [int]$alt.Mail.Port -eq $port) { $alt.Mail.Getestet } else { $null }
    $ziele = if ($script:ZieleGeladen) { Get-GewaehlteZiele } elseif ($alt) { @($alt.Ziele) } else { @() }
    [pscustomobject]@{
        Hostname   = $h
        Kontakt    = $kontakt
        Server     = $(if ($alt -and $alt.Server) { $alt.Server } else { 'LE_PROD' })
        AcmeDns    = $script:AcmeDns
        Ziele      = [string[]]@($ziele | Where-Object { $_ })
        Thumbprint = $(if ($alt) { $alt.Thumbprint } else { $null })
        Mail       = [pscustomobject]@{
            An       = $mailAn
            Von      = $mailVon
            Server   = $mailServer
            Port     = $port
            Getestet = $getestet
        }
    }
}

function Set-AbsenderVorschlag {
    $h = $ui.txtHost.Text.Trim().ToLower().TrimEnd('.')
    if ($ui.txtMailVon.Text.Trim() -or $h -notmatch '\.') { return }
    $teile = $h.Split('.')
    $domain = if ($teile.Count -gt 2) { ($teile[1..($teile.Count - 1)] -join '.') } else { $h }
    $ui.txtMailVon.Text = "info@$domain"
}

function Import-Formular {
    $k = Get-NleKonfig
    if ($k) {
        $ui.txtHost.Text = $k.Hostname
        $ui.txtKontakt.Text = $k.Kontakt
        $script:AcmeDns = $k.AcmeDns
        $ui.txtAcmeServer.Text = if ($k.AcmeDns) { $k.AcmeDns.server } else { $Vorgaben.AcmeDns }
        $script:GespeicherteZiele = @($k.Ziele)
        $ui.txtMailAn.Text = $k.Mail.An
        $ui.txtMailVon.Text = $k.Mail.Von
        $ui.txtSmtp.Text = $k.Mail.Server
        $ui.txtPort.Text = "$($k.Mail.Port)"
        if ($k.Mail.PSObject.Properties['Getestet'] -and $k.Mail.Getestet) {
            Set-Meldung $ui.txtMailStatus "✔ Testmail zuletzt erfolgreich gesendet am $(([DateTime]$k.Mail.Getestet).ToString('dd.MM.yyyy HH:mm'))." ok
        }
        if ($k.AcmeDns -and $k.AcmeDns.Hostname -ne $k.Hostname) {
            # Neue Registrierung für einen anderen Hostnamen, noch nicht mit Schritt 6 übernommen
            $ui.txtHost.Text = $k.AcmeDns.Hostname
            Add-Log "Umstellung auf $($k.AcmeDns.Hostname) begonnen, noch nicht mit Schritt 6 übernommen."
        }
        Add-Log "Konfiguration geladen: $NleKonfig"
    } else {
        $ui.txtKontakt.Text = $Vorgaben.Kontakt
        $ui.txtAcmeServer.Text = $Vorgaben.AcmeDns
        $ui.txtMailAn.Text = $Vorgaben.MailAn
        $ui.txtSmtp.Text = ''
        $ui.txtPort.Text = "$($Vorgaben.SmtpPort)"
        Add-Log 'Noch keine Konfiguration auf diesem Server.'
    }
    if (-not $ui.txtMailStatus.Text) { Set-Meldung $ui.txtMailStatus 'Testmail senden, um die Einstellungen zu prüfen.' hinweis }
    $ui.txtNspBenutzer.Text = if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
    Show-Cname
}

function Invoke-Weiter {
    $w = $script:Weiter
    $script:Weiter = $null
    if ($w) { & $w }
}

function Import-Ziele {
    param([scriptblock]$Weiter)
    $script:Weiter = $Weiter
    Set-Meldung $ui.txtZieleStatus 'Lade Konnektoren ...' hinweis
    Start-Hintergrund -Arbeit { Get-NleZiele } -Danach { param($r) Show-Ziele @($r); Invoke-Weiter } -Fehler {
        param($m)
        Set-Meldung $ui.txtZieleStatus "✘ Konnektoren nicht lesbar: $m" fehler
        Invoke-Weiter
    }
}

function Start-DnsPruefung {
    $h = $script:AcmeDns.Hostname
    Add-Log "Prüfe CNAME _acme-challenge.$h ..."
    Set-Meldung $ui.txtDnsStatus 'Prüfe DNS ...' hinweis
    Start-Hintergrund -Arbeit { param($h, $z) Test-NleCname -Hostname $h -Ziel $z } `
        -Argumente @($h, $script:AcmeDns.fulldomain) -Danach {
        param($r)
        $e = @($r)[-1]
        foreach ($d in $e.Details) {
            $w = if ($d.Wert) { $d.Wert } elseif ($d.Erreicht) { '(kein CNAME)' } else { '(nicht erreichbar)' }
            Add-Log ('    {0,-12} {1}' -f $d.Server, $w)
        }
        $script:DnsOk = [bool]$e.Ok
        if ($e.Ok) {
            Set-Meldung $ui.txtDnsStatus '✔ CNAME ist öffentlich sichtbar.' ok
        } else {
            Set-Meldung $ui.txtDnsStatus '✘ CNAME noch nicht sichtbar – beim Hoster dauert es oft ein paar Minuten, ein alter Wert bis zu einer Stunde.' fehler
        }
    } -Fehler { param($m) Set-Meldung $ui.txtDnsStatus "✘ DNS-Prüfung fehlgeschlagen: $m" fehler }
}

# Update-Prüfung läuft wie die Hostname-Prüfung nebenher, ohne Knöpfe zu sperren
$script:UpdateInfo = $null
$script:UpdatePruefung = $null
$script:UpdateTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:UpdateTimer.Interval = [TimeSpan]::FromMilliseconds(400)
$script:UpdateTimer.Add_Tick({ Update-UpdatePruefung })

function Start-UpdatePruefung {
    if ($script:UpdatePruefung) { return }
    Set-Zeilen $ui.txtUpdate @('–  Suche nach Updates ...')
    $ps = [powershell]::Create()
    [void]$ps.AddScript(". '$($script:Common.Replace("'", "''"))'; Get-NleUpdateInfo")
    $script:UpdatePruefung = @{ PS = $ps; Handle = $ps.BeginInvoke() }
    $script:UpdateTimer.Start()
}

function Update-UpdatePruefung {
    $p = $script:UpdatePruefung
    if (-not $p) { $script:UpdateTimer.Stop(); return }
    if (-not $p.Handle.IsCompleted) { return }
    $script:UpdateTimer.Stop()
    $script:UpdatePruefung = $null
    $r = $null
    $fehler = $null
    try { $r = @($p.PS.EndInvoke($p.Handle))[-1] }
    catch { $fehler = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message } }
    $p.PS.Dispose()
    if (-not $r) { Set-Zeilen $ui.txtUpdate @("–  Update-Prüfung nicht möglich ($fehler)"); return }
    $script:UpdateInfo = $r
    if ($r.Neuer) {
        Set-Zeilen $ui.txtUpdate (@("⚠  Neue Version $($r.Version) verfügbar (installiert: $($r.Installiert))") +
            @($r.Aenderungen | ForEach-Object { "–      $_" }))
        $ui.btnUpdate.Visibility = 'Visible'
        Add-Log "Neue Version $($r.Version) verfügbar."
    } else {
        Set-Zeilen $ui.txtUpdate @("✔  Werkzeug aktuell (Version $($r.Installiert))")
        $ui.btnUpdate.Visibility = 'Collapsed'
    }
}

# Langsame Abfragen (Module, alle geplanten Aufgaben, lokale IP) nebenher; Update-Status nutzt das Ergebnis
$script:Fakten = $null
$script:FaktenPruefung = $null
$script:FaktenTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:FaktenTimer.Interval = [TimeSpan]::FromMilliseconds(300)
$script:FaktenTimer.Add_Tick({ Update-FaktenPruefung })

function Start-FaktenPruefung {
    if ($script:FaktenPruefung) { return }
    $ps = [powershell]::Create()
    [void]$ps.AddScript(". '$($script:Common.Replace("'", "''"))'" + @'

$nsp = Get-Module -ListAvailable -Name NoSpamProxy | Select-Object -First 1
$posh = Get-Module -ListAvailable -Name Posh-ACME | Sort-Object Version -Descending | Select-Object -First 1
[pscustomobject]@{
    Nsp  = $(if ($nsp) { [string]$nsp.Version } else { $null })
    Posh = $(if ($posh) { [string]$posh.Version } else { $null })
    Wacs = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
             Where-Object { $_.TaskName -like 'win-acme*' -and $_.State -ne 'Disabled' } | ForEach-Object { $_.TaskName })
    Ip   = Get-NleLokaleIp
}
'@)
    $script:FaktenPruefung = @{ PS = $ps; Handle = $ps.BeginInvoke() }
    $script:FaktenTimer.Start()
}

function Update-FaktenPruefung {
    $p = $script:FaktenPruefung
    if (-not $p) { $script:FaktenTimer.Stop(); return }
    if (-not $p.Handle.IsCompleted) { return }
    $script:FaktenTimer.Stop()
    $script:FaktenPruefung = $null
    $r = $null
    try { $r = @($p.PS.EndInvoke($p.Handle))[-1] } catch { Add-Log "WARNUNG: Prüfung der Module fehlgeschlagen: $($_.Exception.Message)" }
    $p.PS.Dispose()
    if (-not $r) { $r = [pscustomobject]@{ Nsp = $null; Posh = $null; Wacs = @(); Ip = 'localhost' } }
    $script:Fakten = $r
    if (-not (Get-NleKonfig) -and -not $ui.txtSmtp.Text.Trim()) { $ui.txtSmtp.Text = $r.Ip }
    Update-Status
}

# Ladebalken läuft, solange irgendeine Prüfung oder Aktion arbeitet
$script:Geladen = $false
$script:LadeTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:LadeTimer.Interval = [TimeSpan]::FromMilliseconds(250)
$script:LadeTimer.Add_Tick({ Update-Ladebalken })

function Update-Ladebalken {
    $laeuft = [bool]($script:Aufgabe -or $script:HostPruefung -or $script:UpdatePruefung -or $script:NspName -or $script:FaktenPruefung)
    $ui.prgLaden.Visibility = if ($laeuft) { 'Visible' } else { 'Collapsed' }
    if (-not $laeuft -and -not $script:Geladen) {
        $script:Geladen = $true
        Add-Log ('Start: alle Prüfungen fertig nach {0:n1} s' -f ((Get-Date) - $script:Prozessstart).TotalSeconds)
    }
}

# Hostname aus der SMTP-Begrüßung des eigenen NSP übernehmen (nur wenn das Feld leer ist)
$script:NspName = $null
$script:NspNameTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:NspNameTimer.Interval = [TimeSpan]::FromMilliseconds(300)
$script:NspNameTimer.Add_Tick({ Update-NspNameUebernahme })

function Start-NspNameUebernahme {
    if ($ui.txtHost.Text.Trim()) { Start-HostPruefung; return }
    Set-Zeilen $ui.txtHostPruefung @('–  Lese Hostname aus NoSpamProxy ...')
    $ps = [powershell]::Create()
    [void]$ps.AddScript(". '$($script:Common.Replace("'", "''"))'; Get-NleNspHostname")
    $script:NspName = @{ PS = $ps; Handle = $ps.BeginInvoke() }
    $script:NspNameTimer.Start()
}

function Update-NspNameUebernahme {
    $p = $script:NspName
    if (-not $p) { $script:NspNameTimer.Stop(); return }
    if (-not $p.Handle.IsCompleted) { return }
    $script:NspNameTimer.Stop()
    $script:NspName = $null
    $h = $null
    try { $h = @($p.PS.EndInvoke($p.Handle))[-1] } catch { }
    $p.PS.Dispose()
    if (-not $ui.txtHost.Text.Trim()) {
        if ($h) {
            $ui.txtHost.Text = $h
            Add-Log "Hostname aus NoSpamProxy übernommen: $h"
            Set-AbsenderVorschlag
            Show-Cname
        } else {
            Add-Log 'Hostname ließ sich nicht aus NoSpamProxy lesen (keine Antwort auf 127.0.0.1:25), bitte eintragen.'
        }
    }
    Start-HostPruefung
}

function Start-Pruefungen {
    # Läuft, sobald das Fenster sichtbar ist: Formular füllen, dann alle Prüfungen nebenher –
    # Module/Aufgaben, Updates, Hostname, Konnektoren (wenn ein Schlüssel da ist), danach DNS
    Add-Log ('Start: Fenster sichtbar nach {0:n1} s' -f ((Get-Date) - $script:Prozessstart).TotalSeconds)
    try {
        Import-Formular
        Update-Status
    } catch { Show-Startfehler $_.Exception.Message; $fenster.Close(); return }
    $script:LadeTimer.Start()
    Start-FaktenPruefung
    Start-UpdatePruefung
    Start-NspNameUebernahme
    $dns = {
        $h = $ui.txtHost.Text.Trim().ToLower().TrimEnd('.')
        if ($script:AcmeDns -and $script:AcmeDns.Hostname -eq $h) { Start-DnsPruefung }
    }
    if (Get-NleZugang) { Import-Ziele -Weiter $dns } else { & $dns }
}

#endregion

#region Knöpfe

$ui.txtHost.Add_LostFocus({ Set-AbsenderVorschlag; Show-Cname; Start-HostPruefung })
$ui.txtHost.Add_TextChanged({ Update-HostStatus })
$ui.txtKontakt.Add_TextChanged({ Update-HostStatus })
$ui.btnHostPruefen.Add_Click({ Start-HostPruefung -Immer })

$ui.btnKopName.Add_Click({ if ($ui.txtCnameName.Text) { [System.Windows.Clipboard]::SetText($ui.txtCnameName.Text) } })
$ui.btnKopKurz.Add_Click({ if ($ui.txtCnameKurz.Text) { [System.Windows.Clipboard]::SetText($ui.txtCnameKurz.Text) } })
$ui.btnKopZiel.Add_Click({ if ($ui.txtCnameZiel.Text) { [System.Windows.Clipboard]::SetText($ui.txtCnameZiel.Text + '.') } })

$ui.btnUpdate.Add_Click({
    $i = $script:UpdateInfo
    if (-not $i -or -not $i.Neuer) { return }
    $liste = (@($i.Aenderungen) | ForEach-Object { "•  $_" }) -join "`n"
    if (-not (Show-Frage "Auf Version $($i.Version) aktualisieren?`n`n$liste`n`nDas Fenster startet danach neu, die Einstellungen bleiben erhalten.")) { return }
    Start-Hintergrund -Arbeit {
        param($Info, $Ordner)
        Install-NleUpdate -Info $Info -Programmordner $Ordner
    } -Argumente @($i, $script:Ordner) -Danach {
        Add-Log 'Update installiert, starte neu ...'
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        Start-Process $ps -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$(Join-Path $script:Ordner 'NspLetsEncrypt.ps1')`""
        $fenster.Close()
    }
})

$ui.btnPoshInstall.Add_Click({
    Start-Hintergrund -Arbeit {
        Initialize-NleUmgebung
        Write-NleLog 'Installiere Posh-ACME aus der PowerShell Gallery (für alle Benutzer) ...'
        if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue |
                  Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
        }
        Install-Module -Name Posh-ACME -Scope AllUsers -Force -Repository PSGallery
        Write-NleLog 'Posh-ACME installiert.'
    } -Danach { Start-FaktenPruefung }
})

$ui.btnWacsAus.Add_Click({
    $t = @(Get-ScheduledTask | Where-Object { $_.TaskName -like 'win-acme*' -and $_.State -ne 'Disabled' })
    if (-not $t.Count) { Update-Status; return }
    $frage = "Diese Aufgaben deaktivieren?`n`n$($t.TaskName -join "`n")`n`n" +
             "win-acme würde sonst weiter erneuern und den Empfangskonnektor auf sein eigenes Zertifikat setzen. " +
             "Am besten erst, wenn das neue Zertifikat eingespielt ist."
    if (-not (Show-Frage $frage)) { return }
    $t | Disable-ScheduledTask | Out-Null
    Add-Log "win-acme-Aufgabe deaktiviert: $($t.TaskName -join ', ')"
    Start-FaktenPruefung
})

$ui.btnRegistrieren.Add_Click({
    $k = Read-Formular
    if (-not $k) { return }
    if ($script:AcmeDns -and $script:AcmeDns.Hostname -eq $k.Hostname) {
        $frage = "Für $($k.Hostname) gibt es schon eine Registrierung:`n$($script:AcmeDns.fulldomain)`n`n" +
                 "Trotzdem neu registrieren? Der CNAME beim Hoster muss dann geändert werden."
        if (-not (Show-Frage $frage)) { return }
    }
    $script:RegHost = $k.Hostname
    Start-Hintergrund -Arbeit { param($Server) Register-NleAcmeDns -Server $Server } `
        -Argumente @($ui.txtAcmeServer.Text.Trim()) -Danach {
        param($r)
        $reg = @($r)[-1]
        $script:AcmeDns = [pscustomobject]@{
            Hostname   = $script:RegHost
            server     = $reg.server
            subdomain  = $reg.subdomain
            username   = $reg.username
            password   = $reg.password
            fulldomain = $reg.fulldomain
        }
        $script:DnsOk = $false
        Show-Cname
        Set-Meldung $ui.txtDnsStatus 'CNAME beim Hoster anlegen, dann DNS prüfen.' hinweis
        # Nur die Registrierung speichern; Hostname, Konnektoren usw. übernimmt erst Schritt 6
        $alt = Get-NleKonfig
        if ($alt) {
            $alt.AcmeDns = $script:AcmeDns
            Save-NleKonfig $alt
        } else {
            $k = Read-Formular
            if ($k) { Save-NleKonfig $k }
        }
        Add-Log "Beim Hoster anlegen:  CNAME  $($ui.txtCnameKurz.Text)  ->  $($script:AcmeDns.fulldomain)."
    }
})

$ui.btnDnsPruefen.Add_Click({
    $k = Read-Formular
    if (-not $k) { return }
    if (-not $script:AcmeDns -or $script:AcmeDns.Hostname -ne $k.Hostname) {
        Set-Meldung $ui.txtDnsStatus 'Zuerst auf „Registrieren“ klicken, dann den DNS-Eintrag beim Hoster setzen.' fehler
        return
    }
    Start-DnsPruefung
})

$ui.btnApiKey.Add_Click({
    $benutzer = $ui.txtNspBenutzer.Text.Trim()
    if (-not $benutzer -or -not $ui.pwdNspPasswort.Password) { Add-Log 'Bitte Benutzer und Passwort für NoSpamProxy eintragen.'; return }
    if ((Get-NleZugang) -and -not (Show-Frage 'Es gibt schon einen API-Schlüssel für diesen Server. Durch einen neuen ersetzen?')) { return }
    $passwort = $ui.pwdNspPasswort.SecurePassword
    Start-Hintergrund -Arbeit {
        param($Benutzer, $Passwort)
        New-NleApiSchluessel -Benutzer $Benutzer -Passwort $Passwort
    } -Argumente @($benutzer, $passwort) -Danach {
        $ui.pwdNspPasswort.Clear()
        Update-Status
        Import-Ziele
    } -Fehler { param($m) Set-Meldung $ui.txtApiStatus "✘ $m" fehler }
})

$ui.btnKonnektoren.Add_Click({ Import-Ziele })

$ui.btnTestmail.Add_Click({
    $k = Read-Formular
    if (-not $k) { return }
    $script:TestKonfig = $k
    Set-Meldung $ui.txtMailStatus 'Sende Testmail ...' hinweis
    Start-Hintergrund -Arbeit {
        param($k)
        Send-NleMail -Konfig $k -Betreff "Testmail NspLetsEncrypt ($env:COMPUTERNAME)" `
            -Text "Diese Adresse bekommt eine Mail, wenn die Let's-Encrypt-Erneuerung für $($k.Hostname) auf $env:COMPUTERNAME scheitert."
    } -Argumente @(, $k) -Danach {
        # Nur die Mail-Einstellungen speichern; alles andere übernimmt erst Schritt 6
        $jetzt = Get-Date
        $m = $script:TestKonfig.Mail
        $m.Getestet = $jetzt.ToString('s')
        $alt = Get-NleKonfig
        if ($alt) { $alt.Mail = $m; Save-NleKonfig $alt } else { Save-NleKonfig $script:TestKonfig }
        Set-Meldung $ui.txtMailStatus "✔ Testmail gesendet am $($jetzt.ToString('dd.MM.yyyy HH:mm')) – bitte im Postfach nachsehen." ok
    } -Fehler { param($m) Set-Meldung $ui.txtMailStatus "✘ Testmail fehlgeschlagen: $m" fehler }
})

$ui.btnAblaufTest.Add_Click({
    $k = Read-Formular -Vollstaendig
    if (-not $k) { return }
    if (-not $k.AcmeDns -or $k.AcmeDns.Hostname -ne $k.Hostname) {
        Set-Meldung $ui.txtAblaufStatus '✘ Zuerst in Schritt 4 registrieren und den DNS-Eintrag setzen.' fehler
        return
    }
    if ($script:Fakten -and -not $script:Fakten.Posh) {
        Set-Meldung $ui.txtAblaufStatus '✘ Posh-ACME fehlt, bitte oben im Status installieren.' fehler
        return
    }
    Set-Zeilen $ui.txtAblaufStatus @('–  Teste Abruf bei Let''s Encrypt (Testumgebung), etwa 1 Minute ...')
    Start-Hintergrund -Arbeit {
        param($k)
        $VerbosePreference = 'Continue'
        Test-NleAblauf -Konfig $k
        $VerbosePreference = 'SilentlyContinue'
        # Lesender Test des NSP-Zugangs; ein Fehler hier macht den Abruftest nicht ungültig
        $nsp = try { "✔  NoSpamProxy erreichbar, $(@(Get-NleZiele).Count) Konnektor-Stellen lesbar" }
               catch { "⚠  NoSpamProxy nicht lesbar: $($_.Exception.Message)" }
        Write-NleLog $nsp.Substring(3)
        $nsp
    } -Argumente @(, $k) -Danach {
        param($r)
        Set-Zeilen $ui.txtAblaufStatus @(
            '✔  Ablauf erfolgreich: Let''s Encrypt hat über acme-dns und den CNAME ein Testzertifikat ausgestellt.',
            [string]@($r)[-1],
            '–  Es wurde nichts eingespielt. Ein echtes Zertifikat holt der Knopf daneben.')
    } -Fehler {
        param($m)
        Set-Zeilen $ui.txtAblaufStatus @("✘  Ablauf fehlgeschlagen: $m")
    }
})

$ui.btnAusstellen.Add_Click({
    $k = Read-Formular -Vollstaendig
    if (-not $k) { return }
    if (-not $k.AcmeDns -or $k.AcmeDns.Hostname -ne $k.Hostname) { Add-Log "Erst bei acme-dns registrieren (Schritt 4)."; return }
    if (-not $script:ZieleGeladen -and -not @($k.Ziele).Count) { Add-Log 'Erst die Konnektoren laden und auswählen (Schritt 2).'; return }
    if (-not $script:DnsOk -and -not (Show-Frage 'Die DNS-Prüfung war noch nicht erfolgreich. Trotzdem versuchen?')) { return }
    $umgebung = if ($k.Server -eq 'LE_STAGE') { 'Staging (Test)' } else { 'Produktion' }
    $ziele = if (@($k.Ziele).Count) { "$(@($k.Ziele).Count) Konnektor-Stelle(n)" } else { 'KEINE Konnektoren (nur Zertifikat holen)' }
    if (-not (Show-Frage "Zertifikat für $($k.Hostname) holen ($umgebung) und in $ziele einspielen?`n`nDanach wird die tägliche Erneuerung als SYSTEM eingerichtet.")) { return }
    Save-NleKonfig $k
    $script:GespeicherteZiele = @($k.Ziele)
    Start-Hintergrund -Arbeit {
        param($Quelle, $Erzwingen)
        $k = Get-NleKonfig
        $alt = $k.Thumbprint
        $VerbosePreference = 'Continue'
        $tp = New-NleZertifikat -Konfig $k -Erzwingen:$Erzwingen
        $VerbosePreference = 'SilentlyContinue'
        Set-NleZertifikat -Thumbprint $tp -Schluessel @($k.Ziele)
        $k.Thumbprint = $tp
        Save-NleKonfig $k
        Remove-NleAltesZertifikat -Alt $alt -Neu $tp
        Install-NleErneuerung -QuellOrdner $Quelle
        Write-NleEreignis "Zertifikat $tp für $($k.Hostname) eingerichtet und in NoSpamProxy eingespielt." -Id 1000
        Write-NleLog 'Fertig.'
    } -Argumente @($script:Ordner, [bool]$ui.chkErzwingen.IsChecked) -Danach {
        $ui.chkErzwingen.IsChecked = $false
        Update-Status
        Import-Ziele
    }
})

$ui.btnErneuernJetzt.Add_Click({
    if (-not (Get-ScheduledTask -TaskName $NleTaskName -ErrorAction SilentlyContinue)) {
        Add-Log 'Die Erneuerung ist noch nicht eingerichtet (Schritt 6).'
        return
    }
    Add-Log "Starte Aufgabe '$NleTaskName' ..."
    Start-Hintergrund -Arbeit {
        $log = Join-Path $NleLogOrdner ('{0:yyyy-MM}.log' -f (Get-Date))
        $gelesen = if (Test-Path $log) { @(Get-Content $log -Encoding UTF8).Count } else { 0 }
        Start-ScheduledTask -TaskName $NleTaskName
        Start-Sleep -Seconds 2
        $ende = (Get-Date).AddMinutes(10)
        do {
            Start-Sleep -Seconds 2
            $laeuft = (Get-ScheduledTask -TaskName $NleTaskName).State -eq 'Running'
            if (Test-Path $log) {
                $neu = @(Get-Content $log -Encoding UTF8 | Select-Object -Skip $gelesen)
                foreach ($z in $neu) { Write-Information $z }
                $gelesen += $neu.Count
            }
        } while ($laeuft -and (Get-Date) -lt $ende)
        $info = Get-ScheduledTaskInfo -TaskName $NleTaskName
        if ($info.LastTaskResult -eq 0) { 'Aufgabe erfolgreich beendet.' } else { "Aufgabe beendet mit Ergebnis $($info.LastTaskResult) – siehe Log." }
    } -Danach { param($r) Add-Log (@($r)[-1]); Update-Status }
})

#endregion

$fenster.Add_ContentRendered({ Start-Pruefungen })
[void]$fenster.ShowDialog()
