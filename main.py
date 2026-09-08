import os
import json
import base64
import re
from datetime import datetime
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import pymysql

app = Flask(__name__)
CORS(app)

LINUX_AUDIT_LOG = "/var/log/gmdm_audit.log"
SCRIPTS_DIR = "/opt/mdm_api/scripts"
os.makedirs(SCRIPTS_DIR, exist_ok=True)

DB_CONFIG = {
    'host': 'localhost',
    'user': 'gmdm_user',
    'password': 'UnaNuevaClave123!', 
    'database': 'gmdm_db',
    'autocommit': True,
    'cursorclass': pymysql.cursors.DictCursor,
    'charset': 'utf8mb4'
}

# Diccionario completo de mapeo para auditorÃ­a (Windows + Linux)
NOMBRES_ACCIONES = {
    "SEND_MESSAGE": "Enviar Mensaje",
    "CREATE_IT_USER": "Crear Usuario Local",
    "DESTROY_IT_USER": "Eliminar Usuario Local",
    "ENABLE_RDP": "Habilitar RDP / SSH",
    "DISABLE_RDP": "Deshabilitar RDP / SSH",
    "LOCK_SCREEN": "Bloqueo de Pantalla",
    "ENABLE_BITLOCKER": "Activar BitLocker",
    "REBOOT": "Reinicio del Sistema",
    "SHUTDOWN": "Apagado del Sistema",
    "OS_PATCHES": "ActualizaciÃ³n de Parches (OS/APT)",
    "UPDATE_AGENT": "ActualizaciÃ³n de Agente",
    "TEMP_ADMIN": "ConcesiÃ³n Admin / Sudo Temporal",
    "REVOKE_ADMIN": "RevocaciÃ³n Admin / Sudo",
    "INSTALL_SW": "InstalaciÃ³n de Software (Winget/APT)",
    "UNINSTALL_SW": "DesinstalaciÃ³n de Software (Winget/APT)",
    "QUICK_ASSIST": "Asistencia RÃ¡pida",
    "CUSTOM_PS1": "EjecuciÃ³n de Script Personalizado",
    "WIPE": "Borrado Remoto (WIPE)"
}

def get_db_connection():
    return pymysql.connect(**DB_CONFIG)

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            hostname VARCHAR(100) PRIMARY KEY,
            usuario VARCHAR(100),
            serial VARCHAR(100),
            os VARCHAR(100),
            ram VARCHAR(50),
            disco VARCHAR(50),
            ip_local VARCHAR(50),
            ip_publica VARCHAR(100),
            mac VARCHAR(50),
            bitlocker TEXT,
            software LONGTEXT,
            kbs TEXT,
            agente VARCHAR(50),
            ultima_conexion DATETIME
        )
    ''')
    
    try: c.execute("ALTER TABLE agents ADD COLUMN antivirus VARCHAR(255) DEFAULT 'N/D'")
    except Exception: pass

    try: c.execute("ALTER TABLE agents ADD COLUMN uptime VARCHAR(100) DEFAULT 'N/D'")
    except Exception: pass

    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME,
            hw_token VARCHAR(255),
            admin_email VARCHAR(150),
            action VARCHAR(50),
            status VARCHAR(50),
            details TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS command_queue (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(100),
            comando VARCHAR(50),
            parametro TEXT,
            estado VARCHAR(20) DEFAULT 'PENDING',
            fecha_creacion DATETIME
        )
    ''')

    try: c.execute("ALTER TABLE command_queue ADD COLUMN detalle_resultado TEXT")
    except Exception: pass

    conn.close()

def format_to_pipes(val, field_type='software'):
    if not val:
        return ""
    
    items = []
    if isinstance(val, list):
        for x in val:
            if isinstance(x, dict):
                name = x.get('DisplayName') or x.get('HotFixID') or x.get('name') or ''
                ver = x.get('DisplayVersion') or x.get('Description') or x.get('version') or ''
                items.append(f"{name} ({ver})".strip() if ver else name)
            elif x:
                items.append(str(x).strip())
    else:
        s = str(val).strip()
        if s.startswith('[') and s.endswith(']'):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return format_to_pipes(parsed, field_type)
            except Exception:
                pass
        
        if "||" in s:
            items = [x.strip() for x in s.split("||") if x.strip()]
        elif '\n' in s:
            items = [line.strip() for line in s.splitlines() if line.strip()]
        elif field_type == 'kbs' or 'KB' in s:
            items = re.split(r'\s+(?=KB\d+)', s)
            items = [x.strip() for x in items if x.strip()]
        elif field_type == 'software':
            items = re.split(r'(?<=\))\s+(?=[A-Za-z0-9])', s)
            items = [x.strip() for x in items if x.strip()]
        else:
            items = [s]

    seen = set()
    unique_items = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            unique_items.append(x)

    if field_type == 'software':
        unique_items.sort(key=lambda x: x.lower())

    return "||".join(unique_items)

def validar_login_google(token):
    try:
        parts = token.split('.')
        if len(parts) != 3: return False, "", "GUEST"
        payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.b64decode(payload_padded).decode('utf-8'))
        email = payload.get('email', '').lower()
        
        admins = [
            "fernando.alcala@gigas.com", "ricardo.pinhal@oni.pt",
            "ignacio.garcia@gigas.com", "oscar.cadena@gigas.com",
            "soporte@gigas.com", "pc.pruebas@gigas.com"
        ]
        if email in admins:
            return True, email, "ADMIN"
        return False, email, "GUEST"
    except Exception:
        return False, "", "GUEST"

def register_audit_action(hw_token, admin_email, action, status, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] TOKEN: {hw_token} | ADMIN: {admin_email} | ACCION: {action} | ESTADO: {status} | DETALLES: {details}\n"
    try:
        with open(LINUX_AUDIT_LOG, "a") as f:
            f.write(log_line)
    except PermissionError:
        pass 
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (timestamp, hw_token, admin_email, action, status, details)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (timestamp, hw_token, admin_email, action, status, details))
    except Exception:
        pass
    finally:
        if 'conn' in locals() and conn.open:
            conn.close()

# =================================================================
# SCRIPT DE POWERSHELL INCRUSTADO (DOUBLE TRIGGER + AUTOSTART)
# =================================================================
AGENT_CODE = r"""param([switch]$Once)

# Omite la validaciÃ³n SSL y fuerza TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$ApiUrl = "https://gmdm.gigas.com:8443"
$Token = "Gigas_Sec_2026_x99"
$Version = "v6.9.8"
# ---------------------------------------------------------------------
# AUDITORÍA LOCAL DUAL (CARPETA PÚBLICA + ACCESO DIRECTO EN C:\)
# ---------------------------------------------------------------------
$PublicFolder = "C:\Users\Public\GigasMDM_Audit"
$LogFile      = "$PublicFolder\GigasMDM_Audit.txt"
$OldFolder    = "C:\GigasMDM_Audit"
$SymlinkPath  = "C:\GigasMDM_Audit"

# 1. Limpieza de la carpeta antigua con permisos bloqueados en C:\
if ((Test-Path $OldFolder) -and -not (Get-Item $OldFolder).Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
    try { Remove-Item -Path $OldFolder -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

# 2. Crear carpeta física en ruta Pública si no existe
if (-not (Test-Path $PublicFolder)) {
    New-Item -Path $PublicFolder -ItemType Directory | Out-Null
}

# 3. Aplicar permisos inmutables en la carpeta pública (Lectura para Usuarios)
try {
    $Acl = Get-Acl $PublicFolder
    $Acl.SetAccessRuleProtection($true, $false)
    
    $SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $AdminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $UserRule   = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Usuarios", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
    
    $Acl.AddAccessRule($SystemRule)
    $Acl.AddAccessRule($AdminRule)
    $Acl.AddAccessRule($UserRule)
    Set-Acl -Path $PublicFolder -AclObject $Acl
} catch {}

# 4. Crear acceso directo en C:\ que parece una carpeta física y apunta a la pública
if (-not (Test-Path $SymlinkPath)) {
    try {
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut("$SymlinkPath.lnk")
        $Shortcut.TargetPath = $PublicFolder
        $Shortcut.IconLocation = "%SystemRoot%\system32\shell32.dll,3" # Icono nativo de carpeta de Windows
        $Shortcut.Save()
    } catch {}
}

# 5. Registrar origen en Visor de Eventos si no existe
if (-not [System.Diagnostics.EventLog]::SourceExists("GigasMDM")) {
    try { New-EventLog -LogName "Application" -Source "GigasMDM" -ErrorAction SilentlyContinue } catch {}
}

# 6. Función de escritura en el TXT inmutable y Visor de Eventos
function Write-MDMAuditLog {
    param (
        [string]$Accion,
        [string]$Detalles,
        [int]$EventID = 1000
    )
    $TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogEntry = "[$TimeStamp] [ACCION: $Accion] - $Detalles"
    
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    
    try {
        Write-EventLog -LogName "Application" -Source "GigasMDM" -EntryType Information -EventId $EventID -Message $LogEntry -ErrorAction SilentlyContinue
    } catch {}
}

# Primer registro de arranque
Write-MDMAuditLog -Accion "Inicio de Agente" -Detalles "El agente GigasMDM $Version se ha iniciado correctamente." -EventID 1000
# Primer registro de inicio del agente
Write-MDMAuditLog -Accion "Inicio de Agente" -Detalles "El agente GigasMDM $Version se ha iniciado correctamente." -EventID 1000

$AgentDir = "C:\ProgramData\GigasMDM"
$AgentPath = "C:\ProgramData\GigasMDM\microagente.ps1"
$LegacyPath = "C:\ProgramData\gigas_agent.ps1"

Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "microagente.ps1" -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
if (Test-Path $LegacyPath) { Remove-Item -Path $LegacyPath -Force -ErrorAction SilentlyContinue }

if (-not (Test-Path $AgentDir)) { New-Item -ItemType Directory -Path $AgentDir -Force }
if ($MyInvocation.MyCommand.Path -and ($MyInvocation.MyCommand.Path -ne $AgentPath)) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $AgentPath -Force
}

$RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$RegName = "GigasMDMAgent"
Remove-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue

# --- CREACIÃ“N / ACTUALIZACIÃ“N DE TAREA PROGRAMADA ---
$TaskName = "GigasMDM_Service"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$AgentPath`""
$Trigger1 = New-ScheduledTaskTrigger -AtStartup
$Trigger2 = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit 0

# Sobrescribe siempre la tarea para asegurar que hereda los nuevos triggers
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger @($Trigger1, $Trigger2) -Principal $Principal -Settings $Settings -Force | Out-Null

# Auto-Arranque si no estÃ¡ corriendo tras instalar/actualizar
if ((Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).State -ne 'Running') {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
# ----------------------------------------------------

function Get-Inventory {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $os = $osInfo.Caption
    
    $uptime = "N/D"
    if ($osInfo.LastBootUpTime) {
        $ts = (Get-Date) - $osInfo.LastBootUpTime
        $uptime = "$($ts.Days) dias, $($ts.Hours) horas, $($ts.Minutes) min"
    }

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $ram = if ($cs.TotalPhysicalMemory) { "$([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB" } else { "N/D" }
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
    $disco = if ($disk.Size) { "$([math]::Round($disk.FreeSpace / 1GB, 2)) GB libres de $([math]::Round($disk.Size / 1GB, 2)) GB" } else { "N/D" }
    $serial = (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber
    
    $usuario = $env:USERNAME
    try {
        $owner = (Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue | Select-Object -First 1).User
        if ($owner) { $usuario = $owner }
    } catch {}

    # 1. IP Local y MAC correctas (Solo captura el adaptador con salida a Internet)
    $netInfo = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq "Up" } | Select-Object -First 1
    $ipLocal = if ($netInfo) { $netInfo.IPv4Address.IPAddress } else { "N/D" }
    $mac = if ($netInfo) { $netInfo.NetAdapter.MacAddress } else { "N/D" }

    # 2. IP PÃºblica + GeolocalizaciÃ³n
    $ipPublica = "N/D"
    try {
    $geo = Invoke-RestMethod -Uri "http://ip-api.com/json/" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($geo.status -eq 'success') {
        $ipPublica = "$($geo.query) - $($geo.city), $($geo.countryCode)"
    } else {
        throw "Error API"
    }
} catch {
    try { $ipPublica = (Invoke-RestMethod -Uri 'https://api.ipify.org' -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop).Trim() } catch {}
}
   
    $bitlocker = "N/D"
    try {
        $blVol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($blVol -and $blVol.ProtectionStatus -eq "On") {
            $key = ($blVol.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object -First 1).RecoveryPassword
            if ($key) { $bitlocker = $key } else { $bitlocker = "Cifrado (Sin clave extraÃ­ble)" }
        } elseif ($blVol -and $blVol.ProtectionStatus -eq "Off") {
            $bitlocker = "Desprotegido"
        }
    } catch { $bitlocker = "N/D" }

    $avArray = @()
    try {
        $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntivirusProduct" -ErrorAction SilentlyContinue
        foreach ($av in $avProducts) {
            $stateHex = "{0:x6}" -f $av.productState
            $rtStatus = $stateHex.Substring(2, 2)
            $estado = if ($rtStatus -eq "10" -or $rtStatus -eq "11") { "Activo" } else { "Desactivado" }
            $avArray += "$($av.displayName) [$estado]"
        }
    } catch {}

    if ($avArray.Count -eq 0) {
        $defSvc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($defSvc -and $defSvc.Status -eq "Running") { $avArray += "Windows Defender [Activo]" }
    }
    $antivirus = if ($avArray.Count -gt 0) { ($avArray | Select-Object -Unique) -join "||" } else { "Sin Antivirus Registrado" }
    
    $swArray = @()
    try {
        $swList = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object DisplayName -ne $null
        foreach ($app in $swList) {
            $dn = $app.DisplayName.Trim()
            if ($dn) {
                $ver = if ($app.DisplayVersion) { " ($($app.DisplayVersion))" } else { "" }
                $swArray += "$dn$ver"
            }
        }
    } catch {}
    $sw = ($swArray | Select-Object -Unique) -join "||"

    $kbsArray = @()
    try {
        $kbList = Get-HotFix -ErrorAction SilentlyContinue | Where-Object HotFixID -match "KB" | Sort-Object InstalledOn -Descending
        foreach ($kb in $kbList) {
            if ($kb.HotFixID) { $kbsArray += "$($kb.HotFixID)" }
        }
    } catch {}
    $kbs = ($kbsArray | Select-Object -Unique) -join "||"
    
    return @{
        hostname = $env:COMPUTERNAME
        usuario = $usuario
        serial = $serial
        os = $os
        ram = $ram
        disco = $disco
        ip_local = $ipLocal
        ip_publica = $ipPublica
        mac = $mac
        bitlocker = $bitlocker
        antivirus = $antivirus
        software = $sw
        kbs = $kbs
        agente = $Version
        uptime = $uptime
    }
}

function Send-Callback {
    param([string]$cmd_id, [string]$estado, [string]$detalle)
    try {
        $bodyStr = @{ id = $cmd_id; estado = $estado; detalle = $detalle } | ConvertTo-Json
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyStr)
        Invoke-RestMethod -Uri "$ApiUrl/api/callback" -Method Post -Body $bodyBytes -ContentType "application/json; charset=utf-8" -ErrorAction SilentlyContinue
    } catch {}
}

function Send-Sync {
    try {
        $bodyStr = Get-Inventory | ConvertTo-Json -Depth 5
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyStr)
        $response = Invoke-RestMethod -Uri "$ApiUrl/sync" -Method Post -Body $bodyBytes -ContentType "application/json; charset=utf-8" -ErrorAction Stop
        
        if ($response.status -eq "command") {
            $cmd_id = $response.id
            $comando = $response.comando
            $parametro = $response.parametro
            
            $resultado = "SUCCESS"
            $detalle_error = ""

            try {
                switch ($comando) {
                    "UPDATE_AGENT" {
                        $TmpFile = "$env:TEMP\update_gigas.ps1"
                        Invoke-WebRequest -Uri "$ApiUrl/deploy" -OutFile $TmpFile -ErrorAction Stop
                        Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$TmpFile`" -Once" -Wait -WindowStyle Hidden
                        Remove-Item -Path $TmpFile -Force -ErrorAction SilentlyContinue
                        $detalle_error = "Agente actualizado a v6.9.5 correctamente."
                    }
                    "REBOOT" {
                        Restart-Computer -Force
                        $detalle_error = "Reinicio forzado en proceso."
                    }
                    "SHUTDOWN" {
                        Stop-Computer -Force
                        $detalle_error = "Apagado forzado en proceso."
                    }
                    "SEND_MESSAGE" {
                        msg * $parametro
                        $detalle_error = "Mensaje enviado a la sesion activa."
                    }
                    "CREATE_IT_USER" {
                        $pwd = ConvertTo-SecureString "Temporal_2026!" -AsPlainText -Force
                        New-LocalUser -Name "AdminIT_Temp" -Password $pwd -FullName "Admin IT" -Description "Usuario local temporal" -ErrorAction SilentlyContinue
                        Add-LocalGroupMember -Group "Administradores" -Member "AdminIT_Temp" -ErrorAction SilentlyContinue
                        Add-LocalGroupMember -Group "Administrators" -Member "AdminIT_Temp" -ErrorAction SilentlyContinue
                        $detalle_error = "Usuario AdminIT_Temp creado y anadido al grupo de administradores locales."
                    }
                    "DESTROY_IT_USER" {
                        Remove-LocalUser -Name "AdminIT_Temp" -ErrorAction SilentlyContinue
                        $detalle_error = "Usuario AdminIT_Temp eliminado del equipo."
                    }
                    "ENABLE_RDP" {
                        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
                        Enable-NetFirewallRule -DisplayGroup "Escritorio remoto" -ErrorAction SilentlyContinue
                        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
                        $detalle_error = "Reglas RDP habilitadas."
                    }
                    "DISABLE_RDP" {
                        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1
                        Disable-NetFirewallRule -DisplayGroup "Escritorio remoto" -ErrorAction SilentlyContinue
                        Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
                        $detalle_error = "Conexiones RDP deshabilitadas."
                    }
                    "LOCK_SCREEN" {
                        & "$env:SystemRoot\System32\tsdiscon.exe"
                        $detalle_error = "Sesion activa bloqueada y devuelta a la pantalla de login."
                    }
                    "ENABLE_BITLOCKER" {
                        Enable-BitLocker -MountPoint "C:" -UsedSpaceOnly -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop
                        $detalle_error = "Cifrado Bitlocker iniciado en disco C:."
                    }
                    "OS_PATCHES" {
                        Start-Service wuauserv -ErrorAction SilentlyContinue
                        usoclient StartScan
                        usoclient StartDownload
                        usoclient StartInstall
                        $detalle_error = "Proceso de Windows Update (USOClient) disparado en segundo plano."
                    }
                    "TEMP_ADMIN" {
                        Add-LocalGroupMember -Group "Administradores" -Member $parametro -ErrorAction SilentlyContinue
                        Add-LocalGroupMember -Group "Administrators" -Member $parametro -ErrorAction SilentlyContinue
                        $detalle_error = "Privilegios de Administrador otorgados a la cuenta: $parametro"
                    }
                    "REVOKE_ADMIN" {
                        Remove-LocalGroupMember -Group "Administradores" -Member $parametro -ErrorAction SilentlyContinue
                        Remove-LocalGroupMember -Group "Administrators" -Member $parametro -ErrorAction SilentlyContinue
                        $detalle_error = "Privilegios revocados de la cuenta: $parametro"
                    }
                    "INSTALL_SW" {
                        Start-Process "winget.exe" -ArgumentList "install --id `"$parametro`" --exact --accept-package-agreements --accept-source-agreements --silent" -Wait -WindowStyle Hidden
                        $detalle_error = "Orden de instalacion Winget enviada para: $parametro"
                    }
                    "UNINSTALL_SW" {
                        $cleanSearch = $parametro -replace '\s*\([^\)]*\)\s*$', ''
                        $app = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match [regex]::Escape($cleanSearch) } | Select-Object -First 1
                        if ($app -and $app.QuietUninstallString) {
                            Start-Process cmd.exe -ArgumentList "/c $($app.QuietUninstallString)" -Wait -WindowStyle Hidden
                            $detalle_error = "Desinstalacion silenciosa lanzada."
                        } else {
                            $resultado = "FAILED"
                            $detalle_error = "Cadena de desinstalacion silenciosa no encontrada."
                        }
                    }
                    "QUICK_ASSIST" {
                        Start-Process -FilePath "quickassist.exe" -WindowStyle Normal
                        $detalle_error = "Proceso de Asistencia Rapida invocado."
                    }
                    "CUSTOM_PS1" {
                        $salida = Invoke-Expression $parametro | Out-String
                        $detalle_error = "Script ejecutado. Salida: $salida"
                    }
                    "WIPE" {
                        Start-Process "systemreset.exe" -ArgumentList "-factoryreset" -Wait -WindowStyle Hidden
                        $detalle_error = "PROCESO DE WIPE (RESTABLECIMIENTO DE FABRICA) INICIADO."
                    }
                    Default {
                        $resultado = "FAILED"
                        $detalle_error = "Comando no implementado en el agente: $comando"
                    }
                }
            } catch {
                $resultado = "FAILED"
                $detalle_error = $_.Exception.Message
            }
            
            Send-Callback -cmd_id $cmd_id -estado $resultado -detalle $detalle_error
        }
    } catch {}
}

if ($Once) { Send-Sync } else { while ($true) { Send-Sync; Start-Sleep -Seconds 300 } }
"""

@app.route('/deploy', methods=['GET'])
@app.route('/agent_code', methods=['GET'])
def deploy_agent():
    response = make_response(AGENT_CODE)
    response.headers["Content-Disposition"] = "attachment; filename=microagente.ps1"
    response.headers["Content-type"] = "text/plain"
    return response

@app.route('/sync', methods=['POST'])
def sync():
    data = request.json
    hostname = data.get('hostname')
    if not hostname: return jsonify({"status": "error"}), 400
        
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    software_db = format_to_pipes(data.get('software', ''), 'software')
    kbs_db = format_to_pipes(data.get('kbs', ''), 'kbs')
    antivirus = data.get('antivirus', 'N/D')
    uptime = data.get('uptime', 'N/D')

    # Extrae la IP pÃºblica real reenviada por Apache (X-Forwarded-For) si el agente reporta 'N/D'
    ip_conexion_proxy = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    ip_publica_agente = data.get('ip_publica', 'N/D')
    ip_publica_final = ip_conexion_proxy if (not ip_publica_agente or ip_publica_agente == 'N/D') else ip_publica_agente

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO agents (
            hostname, usuario, serial, os, ram, disco, ip_local, ip_publica, mac, bitlocker, antivirus, software, kbs, agente, ultima_conexion, uptime
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            usuario=VALUES(usuario), serial=VALUES(serial), os=VALUES(os),
            ram=VALUES(ram), disco=VALUES(disco), ip_local=VALUES(ip_local),
            ip_publica=VALUES(ip_publica), mac=VALUES(mac), bitlocker=VALUES(bitlocker),
            antivirus=VALUES(antivirus), software=VALUES(software), kbs=VALUES(kbs), 
            agente=VALUES(agente), ultima_conexion=VALUES(ultima_conexion), uptime=VALUES(uptime)
    ''', (
        hostname, data.get('usuario', ''), data.get('serial', ''), data.get('os', ''),
        data.get('ram', ''), data.get('disco', ''), data.get('ip_local', ''),
        ip_publica_final, data.get('mac', ''), data.get('bitlocker', ''),
        antivirus, software_db, kbs_db, data.get('agente', ''), now, uptime
    ))
    
    c.execute("SELECT id, comando, parametro FROM command_queue WHERE hostname=%s AND estado='PENDING' LIMIT 1", (hostname,))
    cmd = c.fetchone()
    
    if cmd:
        c.execute("UPDATE command_queue SET estado='SENT' WHERE id=%s", (cmd['id'],))
        conn.close()
        return jsonify({"status": "command", "id": cmd['id'], "comando": cmd['comando'], "parametro": cmd['parametro']})
        
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/api/callback', methods=['POST'])
def command_callback():
    data = request.json
    cmd_id = data.get('id')
    estado = data.get('estado')
    detalle = data.get('detalle', '')

    if not cmd_id or not estado: return jsonify({"status": "error"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE command_queue SET estado=%s, detalle_resultado=%s WHERE id=%s", (estado, detalle, cmd_id))
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/queue_command', methods=['POST'])
def queue_command():
    data = request.json
    token = data.get('token')
    es_valido, email, rol = validar_login_google(token)
    if not es_valido or rol != "ADMIN": return jsonify({"status": "error", "msg": "Acceso denegado"}), 403

    hostname = data.get('hostname')
    comando = data.get('comando')
    parametro = data.get('parametro', '')

    if not hostname or not comando: return jsonify({"status": "error"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO command_queue (hostname, comando, parametro, fecha_creacion) VALUES (%s, %s, %s, %s)",
              (hostname, comando, parametro, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.close()

    nombre_humano = NOMBRES_ACCIONES.get(comando, comando)
    register_audit_action(hostname, email, comando, "QUEUED", f"Orden: {nombre_humano} | Parametro: {parametro}")
    return jsonify({"status": "ok", "msg": f"Comando '{nombre_humano}' encolado."})

@app.route('/get_inventory', methods=['GET'])
def get_inventory():
    token = request.args.get('token')
    es_valido, email, rol = validar_login_google(token)
    if not es_valido: return jsonify({"status": "error"}), 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT hostname, usuario, serial, os, ram, disco, ip_local, ip_publica, mac, bitlocker, antivirus, uptime, software, kbs, agente, DATE_FORMAT(ultima_conexion, '%Y-%m-%d %H:%i:%s') AS ultima_conexion FROM agents ORDER BY ultima_conexion DESC")
    inventario = c.fetchall()
    conn.close()
    return jsonify({"status": "ok", "rol": rol, "data": inventario})

@app.route('/get_audit_logs', methods=['GET'])
def get_audit_logs():
    token = request.args.get('token')
    es_valido, email, rol = validar_login_google(token)
    if not es_valido: return jsonify({"status": "error"}), 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT timestamp as fecha, admin_email as admin, action as accion, hw_token, details as detalles FROM audit_logs ORDER BY id DESC LIMIT 500")
    logs = c.fetchall()
    conn.close()
    for log in logs:
        if isinstance(log['fecha'], datetime):
            log['fecha'] = log['fecha'].strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({"status": "ok", "data": logs})

@app.route('/upload_scripts', methods=['POST'])
def upload_scripts():
    token = request.form.get('token')
    es_valido, email, rol = validar_login_google(token)
    if not es_valido or rol != "ADMIN": return jsonify({"status": "error"}), 403

    if 'scripts' not in request.files: return jsonify({"status": "error"}), 400

    archivos = request.files.getlist('scripts')
    for file in archivos:
        if file.filename.endswith('.ps1'):
            filepath = os.path.join(SCRIPTS_DIR, file.filename)
            file.save(filepath)
            register_audit_action("SERVER", email, "UPLOAD_SCRIPT", "SUCCESS", file.filename)

    return jsonify({"status": "ok", "msg": "Scripts subidos."})

@app.route('/get_scripts', methods=['GET'])
def get_scripts():
    token = request.args.get('token')
    es_valido, email, rol = validar_login_google(token)
    if not es_valido: return jsonify({"status": "error"}), 403

    scripts = [f for f in os.listdir(SCRIPTS_DIR) if f.lower().endswith('.ps1')] if os.path.exists(SCRIPTS_DIR) else []
    return jsonify({"status": "ok", "scripts": sorted(scripts)})

@app.route('/api/stats/os', methods=['GET'])
def get_os_stats():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT os, COUNT(*) as total FROM agents GROUP BY os")
    rows = c.fetchall()
    conn.close()
    return jsonify({row['os']: row['total'] for row in rows if row['os']})
@app.route('/api/heartbeat', methods=['POST'])
def linux_heartbeat():
    token = request.headers.get('X-Auth-Token')
    if token != "Gigas_Sec_2026_x99":
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    if not data:
        return jsonify({"error": "Bad Request"}), 400

    hostname = data.get('hostname')
    if not hostname:
        return jsonify({"error": "Missing hostname"}), 400

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Extraer la IP pública real si viene vacía o 'N/D'
    ip_conexion_proxy = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    ip_publica_agente = data.get('ip_publica', 'N/D')
    ip_publica_final = ip_conexion_proxy if (not ip_publica_agente or ip_publica_agente == 'N/D') else ip_publica_agente

    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        c.execute('''
            INSERT INTO agents (
                hostname, usuario, serial, os, ram, disco, ip_local, ip_publica, mac, bitlocker, antivirus, software, kbs, agente, ultima_conexion, uptime, ubicacion
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                usuario=VALUES(usuario), os=VALUES(os), 
                ip_local=VALUES(ip_local), ip_publica=VALUES(ip_publica), 
                agente=VALUES(agente), ultima_conexion=VALUES(ultima_conexion),
                ubicacion=VALUES(ubicacion)
        ''', (
            hostname, 
            data.get('username', 'N/D'), 
            'N/D',                    # serial
            "Linux",                  # os
            'N/D',                    # ram
            'N/D',                    # disco
            data.get('ip_local', 'N/D'),
            ip_publica_final, 
            'N/D',                    # mac
            'N/D',                    # bitlocker
            'N/D',                    # antivirus
            '',                       # software
            '',                       # kbs
            data.get('version', 'N/D'), 
            now,
            'N/D',                    # uptime
            data.get('ubicacion', 'Desconocida') # campo de ubicación
        ))
        
        conn.commit()
        
    except Exception as e:
        conn.close()
        return jsonify({"error": "DB insert failed", "details": str(e)}), 500

    conn.close()
    return jsonify({"status": "ok", "message": "Heartbeat Linux registrado con ubicación"})
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8443, debug=True)
