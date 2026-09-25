import os
import json
import base64
import re
import logging
import hmac
import hashlib
import time
import requests
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from werkzeug.utils import secure_filename
import pymysql
from dbutils.pooled_db import PooledDB

# Configuracion del log fisico del servidor
logging.basicConfig(
    filename='/opt/mdm_api/mdm_audit.log', 
    level=logging.INFO, 
    format='[%(asctime)s] - %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S'
)

# El .env se carga por ruta absoluta y a proposito. Con load_dotenv() a secas
# el fichero se busca en el directorio de trabajo, que bajo systemd no tiene
# por que ser /opt/mdm_api. Si no lo encontraba, el servicio arrancaba igual y
# se quedaba con los valores por defecto que habia escritos mas abajo. Ya no
# hay valores por defecto, asi que esto tiene que funcionar de verdad, y si
# python-dotenv no esta instalado queremos enterarnos en el arranque.
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

app = Flask(__name__)

ALLOWED_ORIGINS = os.getenv('CORS_ORIGINS', 'https://gmdm.gigas.com').split(',')
CORS(app, origins=ALLOWED_ORIGINS)

SCRIPTS_DIR = "/opt/mdm_api/scripts"
os.makedirs(SCRIPTS_DIR, exist_ok=True)

def _secreto(nombre):
    """Lee un secreto del entorno. Sin reserva: si falta, el servicio no arranca.

    Antes cada uno de estos llevaba una cadena escrita aqui como valor por
    defecto. El problema no era tenerla, era que esa cadena resulto ser la
    misma que estaba en produccion, con lo que el .env no protegia de nada y
    cualquiera con el fuente delante tenia las credenciales buenas. Fallar en
    el arranque es ruidoso, pero es preferible a seguir funcionando con una
    credencial publicada.
    """
    valor = os.getenv(nombre)
    if not valor:
        raise RuntimeError(
            "Falta la variable %s. Definela en /opt/mdm_api/.env. "
            "El arranque se aborta a proposito: ya no hay valor por defecto."
            % nombre)
    return valor


AGENT_TOKEN = _secreto('AGENT_TOKEN')
TEMP_ADMIN_PWD = _secreto('TEMP_ADMIN_PWD')

# Token anterior, opcional, y solo mientras dure una rotacion. Con esta linea
# puesta en el .env se aceptan los dos tokens a la vez: los agentes que todavia
# llevan el viejo siguen sincronizando, se autoactualizan y cogen el nuevo.
# Cuando el parque este al dia se borra la linea y se reinicia.
# Sin esto, cambiar AGENT_TOKEN deja fuera a todo el parque de golpe, porque el
# token va embebido en el microagente.ps1 ya instalado en cada equipo.
AGENT_TOKEN_ANTERIOR = os.getenv('AGENT_TOKEN_ANTERIOR', '').strip()
TOKENS_AGENTE = {AGENT_TOKEN}
if AGENT_TOKEN_ANTERIOR:
    TOKENS_AGENTE.add(AGENT_TOKEN_ANTERIOR)
    logging.warning(
        "ROTACION EN CURSO | Se acepta tambien AGENT_TOKEN_ANTERIOR. "
        "Quita esa linea del .env cuando el parque este actualizado.")

db_pool = PooledDB(
    creator=pymysql,
    maxconnections=20,     
    mincached=5,          
    maxcached=10,         
    maxshared=0,          
    blocking=True,        
    host=os.getenv('DB_HOST', 'localhost'),
    user=os.getenv('DB_USER', 'gmdm_user'),
    password=_secreto('DB_PASS'),
    database=os.getenv('DB_NAME', 'gmdm_db'),
    autocommit=True,
    cursorclass=pymysql.cursors.DictCursor,
    charset='utf8mb4'
)

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
    "OS_PATCHES": "Actualizacion de Parches (OS/APT)",
    "UPDATE_AGENT": "Actualizacion de Agente",
    "TEMP_ADMIN": "Concesion Admin / Sudo Temporal",
    "REVOKE_ADMIN": "Revocacion Admin / Sudo",
    "INSTALL_SW": "Instalacion de Software (Winget/APT)",
    "UNINSTALL_SW": "Desinstalacion de Software (Winget/APT)",
    "QUICK_ASSIST": "Asistencia Rapida",
    "CUSTOM_PS1": "Ejecucion de Script Personalizado",
    "WIPE": "Borrado Remoto (WIPE)"
}

def get_db_connection():
    return db_pool.connection()

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

    try: c.execute("ALTER TABLE agents ADD COLUMN ubicacion VARCHAR(100) DEFAULT 'N/D'")
    except Exception: pass

    try: c.execute("ALTER TABLE agents ADD COLUMN fecha_insercion DATETIME DEFAULT CURRENT_TIMESTAMP")
    except Exception: pass
    
    try: c.execute("ALTER TABLE agents ADD COLUMN kbs_pendientes TEXT")
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

    # Desde el parche 22 el agente pregunta por su cola cada 20 segundos en vez
    # de cada 300, asi que esta consulta se hace quince veces mas. Sin indice
    # era un recorrido de la tabla entera cada vez.
    try: c.execute("CREATE INDEX idx_cola_hostname_estado ON command_queue (hostname, estado)")
    except Exception: pass

    # Estado de cada parche, decidido y firmado por un administrador.
    # estado: PENDIENTE | APROBADO | CUARENTENA | BLOQUEADO
    c.execute('''
        CREATE TABLE IF NOT EXISTS patch_estado (
            kb VARCHAR(20) PRIMARY KEY,
            estado VARCHAR(20) NOT NULL DEFAULT 'PENDIENTE',
            motivo TEXT,
            decidido_por VARCHAR(150),
            fecha_decision DATETIME,
            revisar_el DATE
        )
    ''')

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

GOOGLE_CLIENT_ID = os.environ['GOOGLE_CLIENT_ID']
ADMIN_EMAILS = {e.strip().lower() for e in os.getenv('ADMIN_EMAILS', '').split(',') if e.strip()}
ALLOWED_HD = {d.strip().lower() for d in os.getenv('ALLOWED_HD', '').split(',') if d.strip()}

GMDM_SESSION_SECRET = os.environ['GMDM_SESSION_SECRET'].encode()
GMDM_SESSION_TTL = int(os.getenv('GMDM_SESSION_TTL', '28800'))   # 8 horas

_google_request = google_requests.Request()


def validar_id_token_google(token):
    if not token:
        return False, "", "GUEST"

    try:
        claims = google_id_token.verify_oauth2_token(
            token, _google_request, GOOGLE_CLIENT_ID
        )
    except Exception as e:
        logging.warning(f"LOGIN RECHAZADO | Token invalido: {e}")
        return False, "", "GUEST"

    if not claims.get('email_verified'):
        return False, "", "GUEST"

    email = (claims.get('email') or '').lower()

    if ALLOWED_HD and (claims.get('hd') or '').lower() not in ALLOWED_HD:
        logging.warning(f"LOGIN RECHAZADO | Dominio no permitido: {email}")
        return False, email, "GUEST"

    if email in ADMIN_EMAILS:
        return True, email, "ADMIN"

    logging.warning(f"LOGIN RECHAZADO | No autorizado: {email}")
    return False, email, "GUEST"


 
def _firmar_sesion(email, rol, caduca):
    cuerpo = base64.urlsafe_b64encode(
        f"{email}|{rol}|{caduca}".encode()
    ).decode().rstrip('=')
    firma = base64.urlsafe_b64encode(
        hmac.new(GMDM_SESSION_SECRET, cuerpo.encode(), hashlib.sha256).digest()
    ).decode().rstrip('=')
    return f"gmdm1.{cuerpo}.{firma}"
 
 
def _validar_sesion_gmdm(token):
    try:
        _, cuerpo, firma = token.split('.')
    except ValueError:
        logging.warning("LOGIN RECHAZADO | Sesion GMDM malformada")
        return False, "", "GUEST"
 
    esperada = base64.urlsafe_b64encode(
        hmac.new(GMDM_SESSION_SECRET, cuerpo.encode(), hashlib.sha256).digest()
    ).decode().rstrip('=')
 
    if not hmac.compare_digest(firma, esperada):
        logging.warning("LOGIN RECHAZADO | Sesion GMDM con firma invalida")
        return False, "", "GUEST"
 
    try:
        relleno = '=' * (-len(cuerpo) % 4)
        email, rol, caduca = base64.urlsafe_b64decode(cuerpo + relleno).decode().split('|')
    except Exception:
        logging.warning("LOGIN RECHAZADO | Sesion GMDM ilegible")
        return False, "", "GUEST"
 
    if time.time() > float(caduca):
        logging.warning(f"LOGIN RECHAZADO | Sesion GMDM caducada: {email}")
        return False, email, "GUEST"
 
    # Se vuelve a mirar la lista en cada peticion: quitar a alguien de
    # ADMIN_EMAILS y reiniciar lo echa al momento, sin esperar a que caduque.
    if email not in ADMIN_EMAILS:
        logging.warning(f"LOGIN RECHAZADO | Ya no autorizado: {email}")
        return False, email, "GUEST"
 
    return True, email, rol
 
 
def validar_login_google(token):
    """Acepta una sesion de GMDM o, solo al entrar, un ID token de Google."""
    if not token:
        return False, "", "GUEST"
    if token.startswith('gmdm1.'):
        return _validar_sesion_gmdm(token)
    return validar_id_token_google(token)
 
 


# Ordenes cuyo parametro lleva dentro una contrasena en claro (parche 17).
COMANDOS_CON_SECRETO = ("CREATE_IT_USER", "CREATE_TEMP_RDP")
 
 
def _parametro_sin_secreto(comando, parametro):
    """Devuelve el parametro apto para escribirlo en un registro.
 
    Desde el parche 17 el panel manda "usuario||contrasena||horas" en las
    ordenes que crean cuentas. Ese parametro se copiaba tal cual a audit_logs
    y se quedaba en command_queue, con lo que la contrasena de la cuenta
    acababa en claro en la base de datos y visible para siempre en el modal de
    Auditoria del panel. Aqui se sustituye por el nombre y las horas, que es
    lo unico que hace falta saber luego.
    """
    if comando not in COMANDOS_CON_SECRETO:
        return parametro
    trozos = (parametro or "").split("||")
    nombre = trozos[0].strip() if trozos else ""
    horas = trozos[2].strip() if len(trozos) > 2 else ""
    texto = "Usuario: %s | Contrasena: no registrada" % (nombre or "(sin nombre)")
    if horas:
        texto += " | Caducidad: %s h" % horas
    return texto
 
 
def register_audit_action(hw_token, admin_email, action, status, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Escritura en el log fisico inmutable de Linux
    try:
        logging.info(f"TOKEN: {hw_token} | ADMIN: {admin_email} | ACCION: {action} | ESTADO: {status} | DETALLES: {details}")
    except Exception:
        pass
        
    # Escritura en Base de Datos MariaDB
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
        if 'conn' in locals():
            conn.close()

AGENT_CODE = r"""param([switch]$Once)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$ApiUrl = "https://gmdm.gigas.com:8443"
$Token = "{{AGENT_TOKEN}}"
$Version = "v6.9.32"

# Cada cuanto se manda el inventario completo, y cada cuanto se pregunta si hay
# ordenes en cola. Lo segundo es una peticion diminuta; lo primero no.
$IntervaloInventario = 300
$IntervaloSondeo     = 20

$PublicFolder = "C:\Users\Public\GigasMDM_Audit"
$LogFile      = "$PublicFolder\GigasMDM_Audit.txt"
$OldFolder    = "C:\GigasMDM_Audit"
$SymlinkPath  = "C:\GigasMDM_Audit"

if ((Test-Path $OldFolder) -and -not (Get-Item $OldFolder).Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
    try { Remove-Item -Path $OldFolder -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

if (-not (Test-Path $PublicFolder)) {
    New-Item -Path $PublicFolder -ItemType Directory | Out-Null
}

if (-not (Test-Path $LogFile)) {
    "" | Out-File -FilePath $LogFile -Encoding utf8 -Force
}

function Set-HardenedLogAcl {
    try {
        $SidSystem = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $SidAdmins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $SidUsers  = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")

        $FolderAcl = Get-Acl $PublicFolder
        $FolderAcl.SetAccessRuleProtection($true, $false)
        $FolderAcl.Access | ForEach-Object { $FolderAcl.RemoveAccessRule($_) } | Out-Null

        $FolderAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $FolderAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmins, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $FolderAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -Path $PublicFolder -AclObject $FolderAcl

        if (Test-Path $LogFile) {
            $FileAcl = Get-Acl $LogFile
            $FileAcl.SetAccessRuleProtection($true, $false)
            $FileAcl.Access | ForEach-Object { $FileAcl.RemoveAccessRule($_) } | Out-Null

            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmins, "ReadAndExecute", "None", "None", "Allow")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "None", "None", "Allow")))
            Set-Acl -Path $LogFile -AclObject $FileAcl
        }
    } catch {}
}

Set-HardenedLogAcl

if (-not (Test-Path $SymlinkPath)) {
    try {
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut("$SymlinkPath.lnk")
        $Shortcut.TargetPath = $PublicFolder
        $Shortcut.IconLocation = "%SystemRoot%\system32\shell32.dll,3"
        $Shortcut.Save()
    } catch {}
}

if (-not [System.Diagnostics.EventLog]::SourceExists("GigasMDM")) {
    try { New-EventLog -LogName "Application" -Source "GigasMDM" -ErrorAction SilentlyContinue } catch {}
}

function Write-MDMAuditLog {
    param (
        [string]$Accion,
        [string]$Detalles,
        [int]$EventID = 1000
    )
    $TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogEntry = "[$TimeStamp] [ACCION: $Accion] - $Detalles"
    
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    Set-HardenedLogAcl
    
    try {
        Write-EventLog -LogName "Application" -Source "GigasMDM" -EntryType Information -EventId $EventID -Message $LogEntry -ErrorAction SilentlyContinue
    } catch {}
}

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

function Set-HardenedAgentAcl {
    # microagente.ps1 lleva dentro, en claro, el token del agente y la
    # contrasena del administrador local temporal. La carpeta se creaba con
    # New-Item y nunca se le tocaban los permisos, asi que heredaba los de
    # C:\ProgramData, donde el grupo Usuarios tiene lectura. Cualquiera con
    # sesion iniciada en el equipo se llevaba las dos credenciales.
    #
    # Al reves que Set-HardenedLogAcl, que deja leer a Usuarios a proposito
    # para que el tecnico pueda mirar el registro sin elevar, aqui se les quita
    # del todo: solo SYSTEM, que es quien ejecuta la tarea programada, y el
    # grupo de Administradores locales. Se identifican por SID para no depender
    # del idioma de Windows.
    param([string]$Ruta)
    try {
        if (-not (Test-Path $Ruta)) { return }

        $SidSystem = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $SidAdmins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")

        $EsCarpeta = (Get-Item -Path $Ruta -Force).PSIsContainer
        if ($EsCarpeta) { $Herencia = "ContainerInherit,ObjectInherit" } else { $Herencia = "None" }

        $Acl = Get-Acl -Path $Ruta
        $Acl.SetAccessRuleProtection($true, $false)
        foreach ($Regla in @($Acl.Access)) { $Acl.RemoveAccessRule($Regla) | Out-Null }
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", $Herencia, "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmins, "FullControl", $Herencia, "None", "Allow")))
        $Acl.SetOwner($SidAdmins)
        Set-Acl -Path $Ruta -AclObject $Acl -ErrorAction Stop
    } catch {
        Write-MDMAuditLog -Accion "HARDEN_ACL" -Detalles "No se han podido endurecer los permisos de $Ruta : $($_.Exception.Message)" -EventID 1004
    }
}

Set-HardenedAgentAcl -Ruta $AgentDir
Set-HardenedAgentAcl -Ruta $AgentPath

$RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$RegName = "GigasMDMAgent"
Remove-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue

$TaskName = "GigasMDM_Service"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$AgentPath`""
$Trigger1 = New-ScheduledTaskTrigger -AtStartup
$Trigger2 = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit 0 -MultipleInstances IgnoreNew

# Disparador de recuperacion. Si el agente muere, la tarea lo vuelve a levantar
# como mucho 5 minutos despues. Con IgnoreNew, mientras el agente este vivo
# cada disparo se descarta y no hace absolutamente nada.
# Solo se instala si esta tarea es la unica que apunta al agente: con tareas
# duplicadas, un disparador periodico las pondria a matarse entre ellas.
$Disparadores = @($Trigger1, $Trigger2)
$PidioRecuperacion = $false
try {
    $OtrasTareas = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.Actions.Arguments -match "microagente\.ps1" -and $_.TaskName -ne $TaskName
    })
    if ($OtrasTareas.Count -gt 0) {
        $Huerfanas = ($OtrasTareas | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }) -join ", "
        Write-MDMAuditLog -Accion "RECUPERACION_OMITIDA" -Detalles "No se instala el disparador de recuperacion: hay $($OtrasTareas.Count) tarea(s) mas apuntando al agente ($Huerfanas). Limpiarlas primero." -EventID 1006
    } else {
        $Trigger3 = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(5)) -RepetitionInterval (New-TimeSpan -Minutes 5)
        $Disparadores = @($Trigger1, $Trigger2, $Trigger3)
        $PidioRecuperacion = $true
    }
} catch {
    Write-MDMAuditLog -Accion "RECUPERACION_OMITIDA" -Detalles "No se ha podido comprobar si hay tareas duplicadas: $($_.Exception.Message)" -EventID 1006
}

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Disparadores -Principal $Principal -Settings $Settings -Force | Out-Null

# Windows a veces se traga la repeticion sin devolver error. Se comprueba.
if ($PidioRecuperacion) {
    try {
        $Intervalos = @((Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).Triggers | ForEach-Object { $_.Repetition.Interval })
        if ($Intervalos -notcontains "PT5M") {
            Write-MDMAuditLog -Accion "RECUPERACION_FALLIDA" -Detalles "Se pidio el disparador de recuperacion de 5 minutos pero Windows no lo ha guardado. El equipo no se recuperara solo." -EventID 1006
        }
    } catch {
        Write-MDMAuditLog -Accion "RECUPERACION_FALLIDA" -Detalles "No se ha podido releer la tarea para comprobar la repeticion: $($_.Exception.Message)" -EventID 1006
    }
}

if ((Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).State -ne 'Running') {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}

# --- BLOQUEO DE ACTUALIZACIONES AUTOMATICAS (CONTROL MDM) ---
try {
    $WURegBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (-not (Test-Path $WURegBase)) { New-Item -Path $WURegBase -Force | Out-Null }
    $WURegAU = "$WURegBase\AU"
    if (-not (Test-Path $WURegAU)) { New-Item -Path $WURegAU -Force | Out-Null }
    Set-ItemProperty -Path $WURegAU -Name "NoAutoUpdate" -Value 1 -Force
} catch {}

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

    $netInfo = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq "Up" } | Select-Object -First 1
    $ipLocal = if ($netInfo) { $netInfo.IPv4Address.IPAddress } else { "N/D" }
    $mac = if ($netInfo) { $netInfo.NetAdapter.MacAddress } else { "N/D" }

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
   
    # Cuatro estados, no dos. "Desprotegido" tapaba por igual un disco sin
    # cifrar, uno cifrandose y uno cifrado al 100% sin proteccion, que es el
    # caso peligroso porque parece que no se ha hecho nada. El prefijo antes de
    # la barra lo lee el panel; lo de despues es lo que se ensena.
    $bitlocker = "N/D"
    try {
        $blVol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($blVol) {
            $estadoVol = "$($blVol.VolumeStatus)"
            $tiposProtector = @($blVol.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
            $hayArranque = @($tiposProtector | Where-Object { $_ -like "Tpm*" -or $_ -eq "ExternalKey" }).Count -gt 0
            $clave = ($blVol.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object -First 1).RecoveryPassword

            if ($blVol.ProtectionStatus -eq "On") {
                if ($clave) {
                    $bitlocker = "ON|$clave"
                } else {
                    $bitlocker = "ON_SIN_CLAVE|Cifrado y protegido, pero sin clave de recuperacion guardada en este equipo."
                }
            } elseif ($estadoVol -eq "EncryptionInProgress") {
                $bitlocker = "PROGRESO|Cifrando: $($blVol.EncryptionPercentage)% hecho. La proteccion se activa al terminar."
            } elseif ($estadoVol -eq "EncryptionPaused") {
                $bitlocker = "PROGRESO|Cifrado en pausa al $($blVol.EncryptionPercentage)%."
            } elseif ($estadoVol -eq "FullyEncrypted") {
                $aviso = "Disco cifrado al 100% pero con la proteccion DESACTIVADA: la clave maestra se guarda en claro en el propio disco, asi que no protege de nada."
                if (-not $hayArranque) { $aviso += " Le falta el protector de TPM." }
                $bitlocker = "SIN_PROTECCION|$aviso"
            } elseif ($estadoVol -eq "FullyDecrypted" -and $hayArranque) {
                $bitlocker = "PENDIENTE_ARRANQUE|Cifrado programado con protector de TPM, pero sin empezar: falta reiniciar para que Windows haga su prueba de arranque. Si el TPM entrega la clave, el cifrado arranca solo; si no la entrega, no se cifra y el equipo arranca normal."
            } elseif ($estadoVol -like "Decryption*") {
                $bitlocker = "PROGRESO|Descifrando: queda el $($blVol.EncryptionPercentage)%."
            } else {
                $bitlocker = "OFF|Desprotegido"
            }
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
    
    # Buscar parches pendientes (Online=$false usa cache local)
    $kbsPendientesArray = @()
    try {
        $Session = New-Object -ComObject "Microsoft.Update.Session" -ErrorAction Stop
        $Searcher = $Session.CreateUpdateSearcher()
        $Searcher.Online = $false 
        $Pending = $Searcher.Search("IsInstalled=0 and Type='Software'").Updates
        foreach ($upd in $Pending) {
            # Parche 26: el titulo viaja con el KB como "KB123::titulo".
            # Se le quitan los separadores (|| y ::) y los saltos de linea.
            $titulo = ([string]$upd.Title) -replace '\|\||::|[\r\n\t]+', ' '
            $titulo = ($titulo -replace '\s{2,}', ' ').Trim()
            if ($titulo.Length -gt 200) { $titulo = $titulo.Substring(0, 200) }
            foreach ($kb in $upd.KBArticleIDs) {
                $kbsPendientesArray += ('KB' + $kb + '::' + $titulo)
            }
        }
    } catch {}
    $kbs_pendientes = ($kbsPendientesArray | Select-Object -Unique) -join "||"
    # Siempre acaba en "||": con un solo KB no habria separador y el servidor
    # cortaria por los espacios delante de "KB" que puede traer el titulo.
    if ($kbs_pendientes) { $kbs_pendientes += "||" }
    
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
        kbs_pendientes = $kbs_pendientes
        agente = $Version
        uptime = $uptime
    }
}

function Invoke-Winget {
    # Lanza winget y devuelve como acabo, que es lo que el agente nunca miraba.
    #
    # winget.exe se ejecuta por su ruta fisica dentro de WindowsApps, fuera del
    # contexto de la aplicacion empaquetada, y asi no resuelve las DLL de sus
    # dependencias: muere al cargarse con 0xC0000135 sin escribir nada. Por eso
    # se ponen delante del PATH las carpetas de VCLibs y UI.Xaml, solo para
    # este proceso. Comprobado en UC-GIGAS-TESTPC el 23/09/2026.
    param([string]$Argumentos)

    $exe = Get-ChildItem -Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
    if (-not $exe) {
        return @{ codigo = $null; texto = "No se encontro winget.exe en C:\Program Files\WindowsApps."; dependencias = 0 }
    }

    $dependencias = @()
    foreach ($patron in @("Microsoft.VCLibs.140.00.UWPDesktop_*_x64__8wekyb3d8bbwe",
                          "Microsoft.UI.Xaml.2.*_x64__8wekyb3d8bbwe")) {
        $dependencias += @(Get-ChildItem -Path "C:\Program Files\WindowsApps" -Directory -Filter $patron -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }

    $ficheroSalida = "$env:TEMP\gmdm_winget_out.txt"
    $ficheroError = "$env:TEMP\gmdm_winget_err.txt"
    Remove-Item $ficheroSalida, $ficheroError -Force -ErrorAction SilentlyContinue

    $pathAnterior = $env:PATH
    $proceso = $null
    try {
        if ($dependencias.Count -gt 0) {
            $env:PATH = ($dependencias -join ';') + ';' + $env:PATH
        }
        $proceso = Start-Process -FilePath $exe.FullName -ArgumentList $Argumentos -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $ficheroSalida -RedirectStandardError $ficheroError
    } finally {
        $env:PATH = $pathAnterior
    }

    # Winget pinta barras de progreso que destrozan la linea unica que se lee
    # en el modal de Auditoria: solo ASCII, y el final, que es donde esta el
    # motivo del fallo.
    $texto = ((Get-Content $ficheroSalida -Raw -ErrorAction SilentlyContinue) + " " + (Get-Content $ficheroError -Raw -ErrorAction SilentlyContinue))
    $texto = (($texto -replace '[^\x20-\x7E]', ' ') -replace '\s+', ' ').Trim()
    if ($texto.Length -gt 300) { $texto = "..." + $texto.Substring($texto.Length - 300) }
    Remove-Item $ficheroSalida, $ficheroError -Force -ErrorAction SilentlyContinue

    $codigo = $null
    if ($proceso) { $codigo = $proceso.ExitCode }
    return @{ codigo = $codigo; texto = $texto; dependencias = $dependencias.Count }
}

function Send-Callback {
    param([string]$cmd_id, [string]$estado, [string]$detalle)
    try {
        $bodyStr = @{ id = $cmd_id; estado = $estado; detalle = $detalle } | ConvertTo-Json
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyStr)
        Invoke-RestMethod -Uri "$ApiUrl/api/callback" -Method Post -Body $bodyBytes -ContentType "application/json; charset=utf-8" -Headers @{"X-Auth-Token"=$Token} -ErrorAction SilentlyContinue
    } catch {}
}

function Test-HayOrden {
    # La pregunta barata: unos cientos de bytes, sin inventario y sin salir a
    # internet. No recoge la orden ni la marca como enviada, solo mira si hay
    # algo esperando; si lo hay, el ciclo normal de Send-Sync se encarga.
    #
    # Cualquier fallo -red caida, servidor reiniciandose, timeout- se traduce en
    # "no hay". El agente se queda entonces como estaba antes de este parche,
    # esperando al ciclo de inventario, que es un mal menor conocido.
    try {
        $equipo = [uri]::EscapeDataString($env:COMPUTERNAME)
        $r = Invoke-RestMethod -Uri "$ApiUrl/api/hay-orden?hostname=$equipo" -Method Get -Headers @{"X-Auth-Token"=$Token} -TimeoutSec 15 -ErrorAction Stop
        return [bool]$r.hay
    } catch {
        return $false
    }
}

function Send-Sync {
    # Lo mira el bucle principal para vaciar la cola sin esperar. Va en una
    # variable de ambito de script y no como valor de retorno: esta funcion
    # tiene demasiadas ramas como para fiarse de lo que acaba saliendo por la
    # salida estandar de PowerShell.
    $script:OrdenEjecutada = $false
    try {
        $bodyStr = Get-Inventory | ConvertTo-Json -Depth 5
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyStr)
        $response = Invoke-RestMethod -Uri "$ApiUrl/sync" -Method Post -Body $bodyBytes -ContentType "application/json; charset=utf-8" -Headers @{"X-Auth-Token"=$Token} -ErrorAction Stop
        
        if ($response.status -eq "command") {
            $script:OrdenEjecutada = $true
            $cmd_id = $response.id
            $comando = $response.comando
            $parametro = $response.parametro
            
            # El registro local vive en C:\Users\Public y lo lee cualquier
            # usuario del equipo, asi que la contrasena de las ordenes que
            # crean cuentas no entra aqui (parche 17).
            $parametroAuditado = $parametro
            if ($comando -eq "CREATE_IT_USER" -or $comando -eq "CREATE_TEMP_RDP") {
                $parametroAuditado = (($parametro -split '\|\|')[0]) + " (contrasena no registrada)"
            }
            Write-MDMAuditLog -Accion $comando -Detalles "Orden ejecutada desde el panel administrador. Parametro: $parametroAuditado"

            $resultado = "SUCCESS"
            $detalle_error = ""

            try {
                switch ($comando) {
                    "UPDATE_AGENT" {
                        # El agente nuevo, nada mas arrancar, mata todo proceso cuya
                        # linea de comandos contenga microagente.ps1: o sea, a este
                        # mismo. Con -Wait nos quedabamos esperando a nuestro propio
                        # verdugo y no se llegaba nunca al Send-Callback del final.
                        # Por eso aqui se reporta ANTES de lanzarlo, y se sale con
                        # return para no intentar reportar dos veces.
                        $TmpFile = "$env:TEMP\update_gigas.ps1"
                        Invoke-WebRequest -Uri "$ApiUrl/deploy" -OutFile $TmpFile -Headers @{"X-Auth-Token"=$Token} -ErrorAction Stop

                        $descarga = Get-Item -Path $TmpFile -ErrorAction SilentlyContinue
                        if ($null -eq $descarga -or $descarga.Length -lt 1000) {
                            throw "La descarga del agente vino vacia o incompleta."
                        }

                        # No se promete exito: esto solo confirma que el fichero ha
                        # bajado entero y que se ha lanzado. Que la actualizacion haya
                        # funcionado se sabe cuando el equipo reporte la version nueva.
                        Send-Callback -cmd_id $cmd_id -estado "SUCCESS" -detalle (
                            "Actualizacion lanzada desde " + $Version + ". Descargados " +
                            $descarga.Length + " bytes. La version nueva se confirmara " +
                            "en el proximo reporte de este equipo.")

                        Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$TmpFile`" -Once" -WindowStyle Hidden
                        return
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
                        # Parametro: nombre||contrasena||horas
                        #   nombre vacio     -> AdminIT_Temp, como hacia antes
                        #   contrasena vacia -> la del .env del servidor (reserva)
                        #   horas 0 o vacio  -> la cuenta no caduca
                        $trozos = @($parametro -split '\|\|')
                        $nombreCuenta = $trozos[0].Trim()
                        if ([string]::IsNullOrWhiteSpace($nombreCuenta)) { $nombreCuenta = "AdminIT_Temp" }
                        if ($nombreCuenta -notmatch '^[A-Za-z0-9._-]{1,20}$') {
                            throw "Nombre de cuenta no valido: '$nombreCuenta'. Solo letras, numeros, punto, guion y guion bajo, hasta 20 caracteres."
                        }
                        $protegidas = @("Administrador", "Administrator", "Invitado", "Guest", "DefaultAccount", "WDAGUtilityAccount", "AdminIT_Gigas")
                        if ($protegidas -contains $nombreCuenta) {
                            throw "La cuenta '$nombreCuenta' esta protegida y no se toca desde el panel."
                        }
 
                        # Si vienen mas de tres trozos es que la contrasena llevaba
                        # "||" dentro: el ultimo trozo son las horas y todo lo de en
                        # medio es la contrasena. Partir por las bravas dejaria la
                        # cuenta con media contrasena y sin caducidad, y diciendo que
                        # todo ha ido bien.
                        $claveTexto = ""
                        $textoHoras = ""
                        if ($trozos.Count -ge 3) {
                            $claveTexto = ($trozos[1..($trozos.Count - 2)] -join '||')
                            $textoHoras = $trozos[$trozos.Count - 1].Trim()
                        } elseif ($trozos.Count -eq 2) {
                            $claveTexto = $trozos[1]
                        }
                        $conClavePropia = -not [string]::IsNullOrWhiteSpace($claveTexto)
                        if (-not $conClavePropia) { $claveTexto = "{{TEMP_ADMIN_PWD}}" }
 
                        $horasVida = 0
                        if ($textoHoras) {
                            $h = ($textoHoras -replace ',', '.') -as [double]
                            if ($h -gt 0) { $horasVida = $h }
                        }
                        if ($horasVida -gt 8760) {
                            throw "Caducidad no valida: $horasVida horas. El maximo es 8760 (un ano)."
                        }
 
                        # El grupo de administradores locales se llama distinto en
                        # cada idioma de Windows. Se localiza por SID, que es el
                        # mismo en todas partes.
                        $grupoAdmins = (Get-LocalGroup | Where-Object { $_.SID.Value -eq "S-1-5-32-544" }).Name
                        if (-not $grupoAdmins) { $grupoAdmins = "Administradores" }
 
                        # Una cuenta que no ha creado GMDM no se toca. Si no, escribir
                        # el nombre de la cuenta de alguien en el panel le cambiaria la
                        # contrasena y, con caducidad, programaria su borrado.
                        # "Usuario local temporal" es la descripcion que ponia la version
                        # vieja: se admite para poder reutilizar los AdminIT_Temp que ya
                        # hay por el parque.
                        $descripcionesGMDM = @("Cuenta local creada desde GMDM", "Usuario local temporal")
                        $existente = Get-LocalUser -Name $nombreCuenta -ErrorAction SilentlyContinue
                        if ($existente -and ($descripcionesGMDM -notcontains $existente.Description)) {
                            throw "La cuenta local '$nombreCuenta' ya existe y no la creo GMDM. No se toca nada: elige otro nombre."
                        }
 
                        $clave = ConvertTo-SecureString $claveTexto -AsPlainText -Force
                        if ($existente) {
                            Set-LocalUser -Name $nombreCuenta -Password $clave -ErrorAction Stop
                            Set-LocalUser -Name $nombreCuenta -Description "Cuenta local creada desde GMDM" -ErrorAction SilentlyContinue
                            Enable-LocalUser -Name $nombreCuenta -ErrorAction SilentlyContinue
                            $queSeHizo = "ya existia de una vez anterior (la creo GMDM): se le ha puesto la contrasena nueva y se ha habilitado"
                        } else {
                            New-LocalUser -Name $nombreCuenta -Password $clave -FullName "Admin IT (GMDM)" -Description "Cuenta local creada desde GMDM" -ErrorAction Stop | Out-Null
                            $queSeHizo = "creada"
                        }
                        Set-LocalUser -Name $nombreCuenta -PasswordNeverExpires $true -ErrorAction SilentlyContinue
                        Add-LocalGroupMember -Group $grupoAdmins -Member $nombreCuenta -ErrorAction SilentlyContinue
 
                        # Nada se da por bueno sin comprobarlo: el codigo viejo
                        # escribia "usuario creado" pasara lo que pasara.
                        if (-not (Get-LocalUser -Name $nombreCuenta -ErrorAction SilentlyContinue)) {
                            throw "La cuenta $nombreCuenta no existe despues de intentar crearla."
                        }
                        # Get-LocalGroupMember revienta en los equipos que tienen un
                        # SID huerfano en el grupo, que es el caso de ALCALAOFICINA.
                        # Si no devuelve nada no se dice que no sea administrador:
                        # se dice que no se ha podido comprobar.
                        $miembros = @(Get-LocalGroupMember -Group $grupoAdmins -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\')[-1] })
                        if ($miembros.Count -eq 0) { $esAdmin = "no comprobado" }
                        elseif ($miembros -contains $nombreCuenta) { $esAdmin = "SI" }
                        else { $esAdmin = "NO" }
 
                        $caducidad = "sin caducidad"
                        if ($horasVida -le 0) {
                            Set-LocalUser -Name $nombreCuenta -AccountNeverExpires -ErrorAction SilentlyContinue
                        } else {
                            $cuando = (Get-Date).AddHours($horasVida)
 
                            # Red de seguridad. La tarea programada no se ejecuta si el
                            # equipo esta apagado a esa hora; la caducidad de la propia
                            # cuenta si se cumple pase lo que pase, asi que aunque el
                            # borrado se retrase la cuenta ya no sirve para entrar.
                            Set-LocalUser -Name $nombreCuenta -AccountExpires $cuando -ErrorAction SilentlyContinue
 
                            $taskName = "GigasMDM_BorrarCuenta_$nombreCuenta"
                            $psCommand = "Add-Content -Path 'C:\Users\Public\GigasMDM_Audit\GigasMDM_Audit.txt' -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [ACCION: EXPIRE_IT_USER] - Eliminada la cuenta local " + $nombreCuenta + " (Temporizador expirado)'); Remove-LocalGroupMember -Group '" + $grupoAdmins + "' -Member '" + $nombreCuenta + "' -ErrorAction SilentlyContinue; Disable-LocalUser -Name '" + $nombreCuenta + "' -ErrorAction SilentlyContinue; Remove-LocalUser -Name '" + $nombreCuenta + "' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName '" + $taskName + "' -Confirm:`$false"
                            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$psCommand`""
                            $trigger = New-ScheduledTaskTrigger -Once -At $cuando
                            $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                            # StartWhenAvailable: un disparador -Once que se pierde
                            # porque el equipo estaba apagado no se recupera nunca sin
                            # esto, y la cuenta se quedaria viva para siempre.
                            $ajustes = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $ajustes -Force | Out-Null
 
                            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                                $caducidad = "se borra sola el " + $cuando.ToString("yyyy-MM-dd HH:mm") + " (dentro de $horasVida h), y la cuenta caduca a esa hora aunque el borrado se retrase"
                            } else {
                                $caducidad = "AVISO: no se ha podido programar el borrado. La cuenta caduca el " + $cuando.ToString("yyyy-MM-dd HH:mm") + " pero hay que borrarla a mano."
                            }
                        }
 
                        $deDonde = "La contrasena es la que se escribio en el panel y no queda registrada en ningun sitio."
                        if (-not $conClavePropia) {
                            $deDonde = "AVISO: la orden no traia contrasena, asi que se ha usado la de reserva del servidor. Si esperabas otra, recarga el panel con Ctrl+F5 y repite."
                        }
                        $detalle_error = "Cuenta local '$nombreCuenta' $queSeHizo. Administrador local: $esAdmin (grupo $grupoAdmins). Caducidad: $caducidad. $deDonde"
                    }
                    "DESTROY_IT_USER" {
                        # Parametro: nombre de la cuenta. Vacio -> AdminIT_Temp,
                        # que es lo unico que sabia borrar la version vieja.
                        $nombreCuenta = (@($parametro -split '\|\|')[0]).Trim()
                        if ([string]::IsNullOrWhiteSpace($nombreCuenta)) { $nombreCuenta = "AdminIT_Temp" }
                        # Sin esto, Get-LocalUser -Name acepta comodines: un "*" pasaria
                        # la comprobacion de existencia y llegaria a Remove-LocalUser.
                        if ($nombreCuenta -notmatch '^[A-Za-z0-9._-]{1,20}$') {
                            throw "Nombre de cuenta no valido: '$nombreCuenta'. No se admiten comodines."
                        }
 
                        $protegidas = @("Administrador", "Administrator", "Invitado", "Guest", "DefaultAccount", "WDAGUtilityAccount", "AdminIT_Gigas")
                        if ($protegidas -contains $nombreCuenta) {
                            throw "La cuenta '$nombreCuenta' esta protegida y no se elimina desde el panel."
                        }
                        if (-not (Get-LocalUser -Name $nombreCuenta -ErrorAction SilentlyContinue)) {
                            throw "La cuenta local '$nombreCuenta' no existe en este equipo. No se ha borrado nada."
                        }
 
                        $grupoAdmins = (Get-LocalGroup | Where-Object { $_.SID.Value -eq "S-1-5-32-544" }).Name
                        if (-not $grupoAdmins) { $grupoAdmins = "Administradores" }
                        Remove-LocalGroupMember -Group $grupoAdmins -Member $nombreCuenta -ErrorAction SilentlyContinue
                        Unregister-ScheduledTask -TaskName "GigasMDM_BorrarCuenta_$nombreCuenta" -Confirm:$false -ErrorAction SilentlyContinue
                        Unregister-ScheduledTask -TaskName "RevokeAdmin_$nombreCuenta" -Confirm:$false -ErrorAction SilentlyContinue
                        Remove-LocalUser -Name $nombreCuenta -ErrorAction SilentlyContinue
 
                        if (Get-LocalUser -Name $nombreCuenta -ErrorAction SilentlyContinue) {
                            throw "No se ha podido eliminar la cuenta local '$nombreCuenta'."
                        }
                        $detalle_error = "Cuenta local '$nombreCuenta' eliminada, y comprobado que ya no existe. El perfil de C:\Users no se borra."
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
                        $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
                        if (-not $vol) { throw "No se puede leer el estado de BitLocker del disco C: en este equipo." }

                        if ($vol.ProtectionStatus -eq "On") {
                            $detalle_error = "BitLocker ya estaba activo y protegiendo C: ($($vol.VolumeStatus), $($vol.EncryptionPercentage)%, $($vol.EncryptionMethod)). No se ha tocado nada."
                        } else {
                            # Sin un protector capaz de desbloquear el disco durante el
                            # arranque, Windows cifra y deja la clave maestra en claro en
                            # el propio disco. Ese es el estado en el que se quedo TESTPC
                            # ocho dias: cifrado al 100% y sin proteger nada.
                            # PUERTA PREVIA. No se puede preguntar a Windows
                            # "arrancarias solo?" sin reiniciar, pero si se pueden mirar
                            # todas las causas conocidas de que pida la clave en el
                            # arranque. Si falla cualquiera no se toca el disco: el
                            # comando devuelve FAILED con el motivo, y ese es el aviso
                            # para revisar el equipo con alguien delante.
                            $motivos = @()

                            $tpm = Get-Tpm -ErrorAction SilentlyContinue
                            if (-not $tpm -or -not $tpm.TpmPresent) {
                                $motivos += "no tiene TPM"
                            } elseif (-not $tpm.TpmReady) {
                                $motivos += "el TPM esta presente pero no listo (activado: $($tpm.TpmEnabled), inicializado: $($tpm.TpmOwned))"
                            }

                            # En BIOS heredada BitLocker se ata a medidas del firmware que
                            # cambian con cualquier actualizacion de BIOS. Con UEFI y
                            # Secure Boot se ata al PCR 7, que aguanta.
                            $secureBoot = $null
                            try { $secureBoot = Confirm-SecureBootUEFI } catch { $secureBoot = $null }
                            if ($null -eq $secureBoot) {
                                $motivos += "no arranca en UEFI"
                            } elseif (-not $secureBoot) {
                                $motivos += "Secure Boot esta desactivado"
                            }

                            # Una directiva puede obligar a teclear un PIN o meter un USB
                            # en cada arranque, que es justo lo que no queremos en remoto.
                            $fve = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
                            if ($fve -and $fve.UseAdvancedStartup -eq 1) {
                                if ($fve.UseTPMPIN -eq 1 -or $fve.UseTPMKeyPIN -eq 1 -or $fve.UseTPMKey -eq 1) {
                                    $motivos += "una directiva obliga a pedir PIN o llave USB al arrancar"
                                }
                            }

                            if ($motivos.Count -gt 0) {
                                throw "NO SE ACTIVA, y a proposito: este equipo arrancaria pidiendo la clave de recuperacion de 48 digitos, porque $($motivos -join ', y '). No se ha tocado el disco. Queda anotado para revisarlo con el equipo delante."
                            }

                            $tipos = @($vol.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
                            $hayTpm = @($tipos | Where-Object { $_ -like "Tpm*" }).Count -gt 0
                            $cuantasClaves = @($tipos | Where-Object { $_ -eq "RecoveryPassword" }).Count
                            $queSeHizo = @()
                            $pruebaArranque = $false

                            if ("$($vol.VolumeStatus)" -eq "FullyDecrypted") {
                                # Primero el TPM y luego la clave de recuperacion. Al reves
                                # -que es lo que hacia la version vieja- Windows cifra con
                                # clave en claro y la proteccion no se activa nunca.
                                #
                                # Y SIN -SkipHardwareTest, a proposito. Asi Windows no
                                # cifra todavia: en el proximo reinicio hace su propio
                                # ensayo sacando la clave del TPM. Si la saca, cifra. Si
                                # no, no cifra y el equipo arranca normal. Es la unica
                                # garantia de verdad de que una orden lanzada en remoto no
                                # deja a nadie tirado en la pantalla de los 48 digitos.
                                $pruebaArranque = $true
                                if ($hayTpm) {
                                    $queSeHizo += "el cifrado ya estaba programado de un intento anterior; sigue faltando reiniciar"
                                } else {
                                    Enable-BitLocker -MountPoint "C:" -UsedSpaceOnly -TpmProtector -ErrorAction Stop | Out-Null
                                    $hayTpm = $true
                                    $queSeHizo += "programado el cifrado con protector de TPM, a falta de la prueba de arranque"
                                }
                            } elseif (-not $hayTpm) {
                                Add-BitLockerKeyProtector -MountPoint "C:" -TpmProtector -ErrorAction Stop | Out-Null
                                $hayTpm = $true
                                $queSeHizo += "anadido el protector de TPM que faltaba"
                            }

                            # Solo si no habia ninguna: el comando viejo anadia una clave de
                            # 48 digitos en cada intento, y en TESTPC se juntaron tres.
                            if ($cuantasClaves -eq 0) {
                                Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
                                $queSeHizo += "creada la clave de recuperacion"
                            } else {
                                $queSeHizo += "ya habia $cuantasClaves clave(s) de recuperacion, no se anade otra"
                            }

                            # Esto es lo que quita la clave en claro y enciende la
                            # proteccion. No tiene sentido en un disco sin cifrar que esta
                            # esperando a la prueba de arranque.
                            if (-not $pruebaArranque) {
                                Resume-BitLocker -MountPoint "C:" -ErrorAction SilentlyContinue | Out-Null
                            }

                            # Y ahora se comprueba, que es justo lo que no se hacia.
                            $final = $null
                            for ($i = 0; $i -lt 6; $i++) {
                                Start-Sleep -Seconds 5
                                $final = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
                                if ($pruebaArranque) { break }
                                if ($final -and $final.ProtectionStatus -eq "On") { break }
                            }

                            if (-not $final) {
                                $resultado = "FAILED"
                                $detalle_error = "Se ejecuto la activacion ($($queSeHizo -join '; ')) pero despues no se puede leer el estado del disco."
                            } else {
                                $tiposFinal = @($final.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" }) -join ','
                                $comoEsta = "Estado: $($final.VolumeStatus), $($final.EncryptionPercentage)% cifrado, proteccion $($final.ProtectionStatus), metodo $($final.EncryptionMethod). Protectores: $tiposFinal."
                                if ($pruebaArranque) {
                                    if ($tiposFinal -notmatch "Tpm") {
                                        $resultado = "FAILED"
                                        $detalle_error = "Se pidio programar el cifrado pero el protector de TPM no ha quedado puesto. No se ha cifrado nada. $comoEsta"
                                    } else {
                                        $detalle_error = "Cifrado programado en C:, y todavia no se ha cifrado nada a proposito. En el proximo reinicio Windows comprueba por su cuenta que el TPM entrega la clave sin intervencion: si la entrega, empieza a cifrar solo; si no la entrega, no cifra y el equipo arranca con normalidad, sin pedir la clave a nadie. Se ha $($queSeHizo -join '; '). $comoEsta Hay que reiniciar el equipo para que avance."
                                    }
                                } elseif ($final.ProtectionStatus -eq "On") {
                                    $detalle_error = "BitLocker activo y protegiendo C:. Se ha $($queSeHizo -join '; '). $comoEsta La clave de recuperacion aparecera en la ficha del equipo en el proximo sondeo, hasta 5 minutos."
                                } elseif ("$($final.VolumeStatus)" -eq "EncryptionInProgress") {
                                    $detalle_error = "Cifrado en marcha en C: al $($final.EncryptionPercentage)%, con protector de TPM. Se ha $($queSeHizo -join '; '). La proteccion se activa al terminar y se vera en la ficha. $comoEsta"
                                } else {
                                    $resultado = "FAILED"
                                    $detalle_error = "No se ha podido activar la proteccion de C:. Se ha $($queSeHizo -join '; '), pero el disco sigue sin proteger. $comoEsta"
                                }
                            }
                        }
                    }
                    "OS_PATCHES" {
                        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
                            Install-Module PSWindowsUpdate -Force -AllowClobber -ErrorAction SilentlyContinue
                        }
                        Import-Module PSWindowsUpdate
                        
                        if ($parametro -match "^KB\d+") {
                            Install-WindowsUpdate -KBArticleID $parametro -AcceptAll -IgnoreReboot
                            $detalle_error = "Instalacion forzada del parche especifico $parametro completada."
                        } else {
                            Install-WindowsUpdate -AcceptAll -IgnoreReboot
                            $detalle_error = "Instalacion de TODOS los parches pendientes completada."
                        }
                    }
                    "TEMP_ADMIN" {
                        # El panel manda "usuario||horas". Antes se le pasaba la
                        # cadena entera a Add-LocalGroupMember, con lo cual la
                        # llamada fallaba siempre; y como las dos llevaban
                        # -ErrorAction SilentlyContinue y nadie comprobaba el
                        # resultado, el comando terminaba en SUCCESS sin haber
                        # concedido nada. La revocacion, ademas, estaba clavada a
                        # 30 minutos e ignoraba las horas pedidas.
                        $partes = $parametro -split '\|\|'
                        $cuenta = $partes[0].Trim()
                        if ([string]::IsNullOrWhiteSpace($cuenta)) {
                            throw "TEMP_ADMIN: no se ha indicado ninguna cuenta."
                        }
                        $cuentaCorta = ($cuenta -split '\\')[-1]

                        $horas = 4
                        if ($partes.Count -ge 2) {
                            $n = 0
                            if ([int]::TryParse($partes[1].Trim(), [ref]$n)) {
                                $horas = [Math]::Max(1, [Math]::Min($n, 24))
                            }
                        }

                        # El grupo de administradores locales se llama distinto en
                        # cada idioma de Windows; por eso el codigo viejo probaba a
                        # ciegas con los dos nombres. Se resuelve por SID, que es
                        # S-1-5-32-544 en todas las instalaciones.
                        $grupoAdmins = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]

                        $miembros = @(Get-LocalGroupMember -Group $grupoAdmins -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\')[-1] })
                        if ($miembros -notcontains $cuentaCorta) {
                            Add-LocalGroupMember -Group $grupoAdmins -Member $cuenta -ErrorAction Stop
                        }

                        # Y se comprueba, que es justo lo que no se hacia.
                        $miembros = @(Get-LocalGroupMember -Group $grupoAdmins -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\')[-1] })
                        if ($miembros -notcontains $cuentaCorta) {
                            throw "TEMP_ADMIN: '$cuenta' no aparece en el grupo $grupoAdmins despues de anadirla."
                        }

                        $taskName = "RevokeAdmin_" + ($cuenta -replace '[^A-Za-z0-9_.-]', '_')
                        $psCommand = "Add-Content -Path 'C:\Users\Public\GigasMDM_Audit\GigasMDM_Audit.txt' -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [ACCION: REVOKE_TEMP_ADMIN] - Revocado privilegio de admin a " + $cuenta + " (Temporizador expirado)'); Remove-LocalGroupMember -Group '" + $grupoAdmins + "' -Member '" + $cuenta + "' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName '" + $taskName + "' -Confirm:`$false"
                        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$psCommand`""
                        $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddHours($horas))
                        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

                        $detalle_error = "Privilegios de administrador concedidos a '$cuenta' en el grupo $grupoAdmins. Revocacion automatica programada dentro de $horas h (tarea $taskName)."
                    }
                    "REVOKE_ADMIN" {
                        # Mismo defecto que TEMP_ADMIN: quitaba a ciegas de los dos
                        # nombres posibles del grupo y reportaba SUCCESS pasara lo
                        # que pasara, incluso si la cuenta no existia.
                        $cuenta = (($parametro -split '\|\|')[0]).Trim()
                        if ([string]::IsNullOrWhiteSpace($cuenta)) {
                            throw "REVOKE_ADMIN: no se ha indicado ninguna cuenta."
                        }
                        $cuentaCorta = ($cuenta -split '\\')[-1]
                        $grupoAdmins = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]

                        Remove-LocalGroupMember -Group $grupoAdmins -Member $cuenta -ErrorAction SilentlyContinue

                        $miembros = @(Get-LocalGroupMember -Group $grupoAdmins -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\')[-1] })
                        if ($miembros -contains $cuentaCorta) {
                            throw "REVOKE_ADMIN: '$cuenta' sigue perteneciendo al grupo $grupoAdmins."
                        }

                        $taskName = "RevokeAdmin_" + ($cuenta -replace '[^A-Za-z0-9_.-]', '_')
                        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                        # Por si quedo alguna tarea con el nombre viejo, que se
                        # formaba con el parametro sin partir ("usuario||horas").
                        Unregister-ScheduledTask -TaskName "RevokeAdmin_$parametro" -Confirm:$false -ErrorAction SilentlyContinue

                        $detalle_error = "Privilegios de administrador retirados a '$cuenta' del grupo $grupoAdmins."
                    }
                    "INSTALL_SW" {
                        $SysWinget = Get-ChildItem -Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
                        if (-not $SysWinget) {
                            throw "No se encontro el binario fisico de Winget en C:\Program Files\WindowsApps."
                        }
                        $WingetPath = $SysWinget.FullName
 
                        # winget.exe lanzado por su ruta fisica, fuera del contexto de
                        # la aplicacion empaquetada, no resuelve las DLL de VCLibs ni
                        # las de UI.Xaml: el proceso muere al cargarse con 0xC0000135
                        # sin escribir nada. Se ponen esas carpetas delante de la ruta
                        # de busqueda, solo para este proceso.
                        $dependencias = @()
                        foreach ($patron in @("Microsoft.VCLibs.140.00.UWPDesktop_*_x64__8wekyb3d8bbwe",
                                              "Microsoft.UI.Xaml.2.*_x64__8wekyb3d8bbwe")) {
                            $dependencias += @(Get-ChildItem -Path "C:\Program Files\WindowsApps" -Directory -Filter $patron -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
                        }
 
                        $ficheroSalida = "$env:TEMP\gmdm_winget_out.txt"
                        $ficheroError = "$env:TEMP\gmdm_winget_err.txt"
                        Remove-Item $ficheroSalida, $ficheroError -Force -ErrorAction SilentlyContinue
 
                        $InstallArgs = "install --id `"$parametro`" --exact --accept-package-agreements --accept-source-agreements --silent --force"
 
                        $pathAnterior = $env:PATH
                        try {
                            if ($dependencias.Count -gt 0) {
                                $env:PATH = ($dependencias -join ';') + ';' + $env:PATH
                            }
                            $proceso = Start-Process -FilePath $WingetPath -ArgumentList $InstallArgs -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $ficheroSalida -RedirectStandardError $ficheroError
                        } finally {
                            $env:PATH = $pathAnterior
                        }
 
                        # Winget pinta barras de progreso con caracteres que destrozan
                        # la linea del modal de Auditoria: se deja solo ASCII y se
                        # recorta al final, que es donde esta el motivo del fallo.
                        $textoWinget = ((Get-Content $ficheroSalida -Raw -ErrorAction SilentlyContinue) + " " + (Get-Content $ficheroError -Raw -ErrorAction SilentlyContinue))
                        $textoWinget = ($textoWinget -replace '[^\x20-\x7E]', ' ') -replace '\s+', ' '
                        $textoWinget = $textoWinget.Trim()
                        if ($textoWinget.Length -gt 400) { $textoWinget = "..." + $textoWinget.Substring($textoWinget.Length - 400) }
                        Remove-Item $ficheroSalida, $ficheroError -Force -ErrorAction SilentlyContinue
 
                        $codigoWinget = $null
                        if ($proceso) { $codigoWinget = $proceso.ExitCode }
 
                        if ($null -eq $codigoWinget) {
                            $resultado = "FAILED"
                            $detalle_error = "Winget ni siquiera llego a ejecutarse. Binario: $WingetPath. Dependencias encontradas: $($dependencias.Count)."
                        } elseif ($codigoWinget -eq 0) {
                            $detalle_error = "Instalado '$parametro'. Winget termino con codigo 0. Binario: $WingetPath."
                            if ($textoWinget) { $detalle_error += " Salida: $textoWinget" }
                        } else {
                            $hex = "0x{0:X8}" -f $codigoWinget
                            $resultado = "FAILED"
                            $pista = ""
                            if ($hex -eq "0xC0000135") {
                                $pista = " Ese codigo significa que falta una DLL: winget no ha podido arrancar. Faltan sus dependencias (VCLibs, UI.Xaml) o no se han encontrado en WindowsApps: se encontraron $($dependencias.Count)."
                            }
                            $detalle_error = "Winget fallo al instalar '$parametro'. Codigo $codigoWinget ($hex).$pista"
                            if ($textoWinget) { $detalle_error += " Salida: $textoWinget" } else { $detalle_error += " Winget no escribio nada." }
                        }
                    }
                    "UNINSTALL_SW" {
                        # El panel manda el nombre tal como se ve en el inventario,
                        # con la version entre parentesis al final. Se quita.
                        $busca = ($parametro -replace '\s*\([^\)]*\)\s*$', '').Trim()
                        if (-not $busca) {
                            throw "No se ha indicado que programa desinstalar."
                        }

                        $clavesDesinstalacion = @(
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
                        )
                        $instalados = @(Get-ItemProperty $clavesDesinstalacion -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })

                        # Primero el nombre exacto. Solo si no hay ninguno se busca por
                        # coincidencia parcial, y si esa coincidencia da mas de un
                        # programa se para: el codigo viejo se quedaba con el primero,
                        # asi que "Google" podia desinstalar cualquier cosa.
                        $exactos = @($instalados | Where-Object { $_.DisplayName.Trim() -eq $busca })
                        if ($exactos.Count -gt 0) {
                            $candidatos = $exactos
                        } else {
                            $candidatos = @($instalados | Where-Object { $_.DisplayName -match [regex]::Escape($busca) })
                        }
                        $nombresDistintos = @($candidatos | ForEach-Object { $_.DisplayName.Trim() } | Select-Object -Unique)
                        if ($nombresDistintos.Count -gt 1) {
                            throw "'$busca' coincide con varios programas ($($nombresDistintos -join ' / ')). Escribe el nombre completo, que desinstalar el que no era no tiene vuelta atras."
                        }

                        $app = $candidatos | Select-Object -First 1
                        $nombreReal = if ($app) { $app.DisplayName.Trim() } else { $busca }
                        $estabaEnRegistro = [bool]$app

                        $via = ""
                        $codigoDes = $null
                        $textoDes = ""

                        if ($app -and $app.QuietUninstallString) {
                            $via = "su propia cadena silenciosa"
                            $p = Start-Process cmd.exe -ArgumentList "/c $($app.QuietUninstallString)" -Wait -PassThru -WindowStyle Hidden
                            if ($p) { $codigoDes = $p.ExitCode }
                        } elseif ($app -and $app.UninstallString -match '(?i)msiexec') {
                            $via = "msiexec"
                            # Basta con el GUID. El codigo viejo reescribia la cadena
                            # entera sustituyendo /I por /X en todo el texto.
                            $guid = ""
                            if ($app.UninstallString -match '\{[0-9A-Fa-f\-]{36}\}') { $guid = $Matches[0] }
                            if (-not $guid) {
                                throw "'$nombreReal' dice desinstalarse con msiexec pero su cadena no lleva ningun GUID: $($app.UninstallString)"
                            }
                            $p = Start-Process msiexec.exe -ArgumentList "/X$guid /qn /norestart" -Wait -PassThru -WindowStyle Hidden
                            if ($p) { $codigoDes = $p.ExitCode }
                        } else {
                            # Aqui es donde fallaba: un .exe con instalador propio y sin
                            # cadena silenciosa. Win32_Product no servia de nada porque
                            # solo conoce MSI, ademas de reconfigurar todos los paquetes
                            # de la maquina al consultarlo. Winget si sabe, y ademas
                            # conoce paquetes que no estan en esas claves del registro,
                            # asi que tambien se intenta cuando la busqueda no da nada.
                            $via = "winget"
                            $r = Invoke-Winget "uninstall --name `"$nombreReal`" --exact --silent --accept-source-agreements"
                            $codigoDes = $r.codigo
                            $textoDes = $r.texto
                        }

                        # Nada se da por bueno sin comprobarlo: se vuelve a leer el
                        # registro. Los desinstaladores tardan un momento en quitar su
                        # entrada despues de terminar.
                        Start-Sleep -Seconds 5
                        $sigueAhi = @(Get-ItemProperty $clavesDesinstalacion -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -eq $nombreReal })

                        $hex = ""
                        if ($null -ne $codigoDes) { $hex = " (0x{0:X8})" -f $codigoDes }

                        if ($sigueAhi.Count -gt 0) {
                            $resultado = "FAILED"
                            $detalle_error = "No se ha podido desinstalar '$nombreReal' mediante $via. Codigo $codigoDes$hex. Sigue apareciendo en el registro."
                        } elseif (-not $estabaEnRegistro) {
                            # Que no este en el registro no prueba nada si tampoco estaba
                            # antes de empezar: aqui la unica prueba es el codigo de
                            # winget. Sin esto, desinstalar algo inexistente saldria bien.
                            if ($codigoDes -eq 0) {
                                $detalle_error = "Desinstalado '$nombreReal' mediante winget. No figuraba en las claves de desinstalacion del registro, asi que el inventario del panel probablemente tampoco lo mostraba."
                            } else {
                                $resultado = "FAILED"
                                $detalle_error = "No se encontro '$nombreReal' instalado en este equipo, y winget tampoco ha podido quitarlo. Codigo $codigoDes$hex."
                            }
                        } else {
                            $detalle_error = "Desinstalado '$nombreReal' mediante $via. Codigo $codigoDes$hex. Comprobado: ya no aparece en el registro."
                            # 3010 es el codigo de msiexec para "hecho, pero hace falta
                            # reiniciar para terminar de quitarlo".
                            if ($codigoDes -eq 3010) { $detalle_error += " Pide un reinicio para completarse." }
                        }
                        if ($textoDes) { $detalle_error += " Salida: $textoDes" }
                    }
                    "QUICK_ASSIST" {
                        # Quick Assist ya no es un .exe de System32: es una app MSIX.
                        # SYSTEM no puede lanzarla (no ve el alias de WindowsApps y una
                        # ventana abierta desde la sesion 0 seria invisible). Hay que
                        # lanzarla como el usuario que tiene la sesion interactiva.
 
                        # 1. Quien esta delante del equipo, sin depender del idioma
                        $procExplorer = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" |
                                        Select-Object -First 1
                        if (-not $procExplorer) {
                            throw "No hay ninguna sesion interactiva abierta en el equipo."
                        }
                        $duenyo  = Invoke-CimMethod -InputObject $procExplorer -MethodName GetOwner
                        $usuario = "$($duenyo.Domain)\$($duenyo.User)"
 
                        # 2. Localizar el paquete y su identificador real de aplicacion
                        $paquete = Get-AppxPackage -AllUsers *QuickAssist* | Select-Object -First 1
                        if (-not $paquete) {
                            throw "Quick Assist no esta instalado en este equipo."
                        }
                        # Get-AppxPackageManifest no funciona bajo SYSTEM: devuelve vacio y no
                        # lanza excepcion, porque el paquete esta registrado en el perfil del
                        # usuario y no en el de la cuenta de maquina. Se lee el manifiesto
                        # directamente del disco, que SYSTEM si puede leer.
                        $appId = ""
                        try {
                            $manifiesto = Join-Path $paquete.InstallLocation "AppxManifest.xml"
                            if (Test-Path $manifiesto) {
                                $xml = [xml](Get-Content -LiteralPath $manifiesto -Raw)
                                $appId = @($xml.Package.Applications.Application)[0].Id
                            }
                        } catch {
                            $appId = ""
                        }
                        if (-not $appId) { $appId = "App" }
                        $destino = "shell:AppsFolder\$($paquete.PackageFamilyName)!$appId"
 
                        # 3. Si ya hay una Asistencia Rapida abierta en la sesion de ese
                        #    usuario, cerrarla antes de nada.
                        #
                        #    "shell:AppsFolder\..." no arranca un proceso: ACTIVA la
                        #    aplicacion. Si la que hay esta colgada de una sesion anterior,
                        #    volver a activarla solo le trae al usuario la misma ventana
                        #    muerta. Se cierra ORDENADO primero, porque cerrar bien es lo
                        #    que le da a la app la ocasion de dejar limpio su estado en el
                        #    perfil; matarla es el plan B.
                        #
                        #    OJO: esto significa que lanzar QUICK_ASSIST dos veces corta
                        #    cualquier sesion en curso. Es deliberado.
                        $sesion = $procExplorer.SessionId
                        $pasos  = @()
 
                        #    El parametro admite "codigo" o "codigo||reset". Con ||reset se
                        #    aparta el estado de la app aunque parezca arrancar bien: es el
                        #    caso del equipo que abre ventana y se queda "conectado" para
                        #    siempre. El automatico de mas abajo solo salta si NO arranca.
                        $trozosQA    = @($parametro -split '\|\|')
                        $codigo      = $trozosQA[0].Trim()
                        $forzarReset = ($trozosQA.Count -gt 1) -and ($trozosQA[1].Trim() -ieq "reset")
 
                        $previas = @(Get-Process -Name "*QuickAssist*" -ErrorAction SilentlyContinue |
                                     Where-Object { $_.SessionId -eq $sesion })
                        if ($previas.Count -gt 0) {
                            foreach ($p in $previas) {
                                try { $null = $p.CloseMainWindow() } catch { }
                            }
                            Start-Sleep -Seconds 3
                            $siguen = @(Get-Process -Name "*QuickAssist*" -ErrorAction SilentlyContinue |
                                        Where-Object { $_.SessionId -eq $sesion })
                            if ($siguen.Count -gt 0) {
                                $siguen | Stop-Process -Force -ErrorAction SilentlyContinue
                                Start-Sleep -Seconds 2
                                $pasos += "habia $($previas.Count) instancia(s) previa(s), no se cerraron solas y se mataron"
                            } else {
                                $pasos += "habia $($previas.Count) instancia(s) previa(s), cerradas ordenadamente"
                            }
                        } else {
                            $pasos += "no habia instancia previa"
                        }
 
                        # 4. Preparar el apartado del estado de la app en el perfil del
                        #    usuario. Una sesion que acabo mal deja ahi dentro una sesion
                        #    marcada como viva, y eso no se lo lleva ni un reinicio ni matar
                        #    procesos: solo restablecer la app. Se RENOMBRA la carpeta, no se
                        #    borra, para que sea reversible y quede rastro; la app se recrea
                        #    su estado sola en el siguiente arranque. Tiene que hacerse con
                        #    la app cerrada, por eso va despues del paso 3.
                        $apartarEstado = {
                            try {
                                $sid = (New-Object System.Security.Principal.NTAccount($usuario)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                                $perfil = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction Stop).ProfileImagePath
                                $carpetaEstado = Join-Path $perfil "AppData\Local\Packages\$($paquete.PackageFamilyName)"
                                if (Test-Path -LiteralPath $carpetaEstado) {
                                    $nombreApartado = (Split-Path $carpetaEstado -Leaf) + ".GMDM-apartado-" + (Get-Date -Format "yyyyMMdd-HHmmss")
                                    Rename-Item -LiteralPath $carpetaEstado -NewName $nombreApartado -ErrorAction Stop
                                    "estado de la app apartado como $nombreApartado"
                                } else {
                                    "no habia carpeta de estado que apartar"
                                }
                            } catch {
                                "no se pudo apartar el estado: $($_.Exception.Message)"
                            }
                        }
 
                        if ($forzarReset) { $pasos += (& $apartarEstado) }
 
                        # 5. Lanzarla en la sesion del usuario y comprobar que arranca de
                        #    verdad. La condicion es que aparezca un proceso en ESA sesion.
                        #    No se exige ventana: desde la sesion 0, donde corre el agente,
                        #    MainWindowHandle puede venir a cero aunque la ventana exista,
                        #    porque las ventanas se enumeran por escritorio. Se apunta como
                        #    dato en el resultado, no como condicion.
                        $lanzar = {
                            $nombreTarea = "GMDM_QuickAssist_" + [guid]::NewGuid().ToString('N').Substring(0,8)
                            try {
                                $accion    = New-ScheduledTaskAction -Execute "explorer.exe" -Argument $destino
                                $principal = New-ScheduledTaskPrincipal -UserId $usuario -LogonType Interactive -RunLevel Limited
                                Register-ScheduledTask -TaskName $nombreTarea -Action $accion -Principal $principal -Force | Out-Null
                                Start-ScheduledTask -TaskName $nombreTarea
                                Start-Sleep -Seconds 2
                            } finally {
                                Unregister-ScheduledTask -TaskName $nombreTarea -Confirm:$false -ErrorAction SilentlyContinue
                            }
                            $encontrado = $null
                            for ($intento = 0; $intento -lt 12; $intento++) {
                                $encontrado = Get-Process -Name "*QuickAssist*" -ErrorAction SilentlyContinue |
                                              Where-Object { $_.SessionId -eq $sesion } |
                                              Select-Object -First 1
                                if ($encontrado) { break }
                                Start-Sleep -Seconds 1
                            }
                            $encontrado
                        }
 
                        $proceso = & $lanzar
 
                        # 6. Si no ha arrancado, apartar el estado y volver a intentarlo.
                        #    Este es el peldano que arregla el fallo solo, sin que nadie
                        #    tenga que ir a Configuracion. Si ya se aparto arriba por
                        #    ||reset, no se repite.
                        if (-not $proceso) {
                            $pasos += "no arranco al primer intento"
                            if (-not $forzarReset) { $pasos += (& $apartarEstado) }
                            $proceso = & $lanzar
                        }
 
                        # 7. El aviso con el codigo, al final: cuando ya hay algo abierto.
                        #    Antes salia el primero, y si la ventana no llegaba a aparecer el
                        #    usuario se quedaba con un codigo en la mano y sin donde meterlo.
                        if ($proceso -and $codigo) {
                            $texto = "Soporte de Gigas va a conectarse a tu equipo. Se abrira la " +
                                     "Asistencia Rapida de Windows: escribe el codigo $codigo y pulsa Enviar."
                            msg * /TIME:180 $texto
                        }
 
                        $comoFue = [string]::Join("; ", $pasos)
                        if ($proceso) {
                            $conVentana = if ($proceso.MainWindowHandle -ne 0) { "con ventana visible" } else { "sin ventana visible desde la sesion 0, que puede ser normal" }
                            $detalle_error = "Asistencia Rapida abierta en la sesion de $usuario (PID $($proceso.Id), $conVentana)" +
                                             $(if ($codigo) { " con el codigo $codigo." } else { " sin codigo." }) +
                                             " Pasos: $comoFue."
                        } else {
                            $resultado = "FAILED"
                            $detalle_error = "No he conseguido abrir la Asistencia Rapida en la sesion de $usuario. " +
                                             "Pasos: $comoFue. Si el equipo llega hasta aqui limpio, el problema no esta " +
                                             "en el equipo remoto: mirar el lado del que ayuda o el camino de red."
                        }
                    }
                    "CUSTOM_PS1" {
                        # El panel manda SOLO el nombre del .ps1 que hay subido en el
                        # servidor, no codigo. Antes se buscaba el fichero en disco,
                        # donde no habia estado nunca porque ninguna ruta lo entregaba,
                        # y se acababa haciendo Invoke-Expression del nombre. De ahi el
                        # error "El termino 'prueba.ps1' no se reconoce...".
                        # Ahora se descarga primero de /get_script_content.
                        $nombre = [System.IO.Path]::GetFileName($parametro)
                        if ([string]::IsNullOrWhiteSpace($nombre) -or $nombre -notmatch '\.ps1$') {
                            throw "Nombre de script no valido: '$parametro'. Se esperaba un .ps1."
                        }

                        $destino = Join-Path "C:\ProgramData\GigasMDM" $nombre
                        $url = "$ApiUrl/get_script_content?nombre=" + [System.Uri]::EscapeDataString($nombre)
                        Invoke-WebRequest -Uri $url -OutFile $destino -Headers @{"X-Auth-Token"=$Token} -ErrorAction Stop

                        $bajado = Get-Item -Path $destino -ErrorAction SilentlyContinue
                        if ($null -eq $bajado -or $bajado.Length -eq 0) {
                            throw "El servidor no devolvio contenido para '$nombre'."
                        }

                        $salida = & powershell.exe -ExecutionPolicy Bypass -NonInteractive -File $destino 2>&1 | Out-String
                        $codigo = $LASTEXITCODE

                        if ($null -ne $codigo -and $codigo -ne 0) {
                            $resultado = "FAILED"
                            $detalle_error = "El script '$nombre' termino con codigo $codigo. Salida: $salida"
                        } else {
                            $detalle_error = "Script '$nombre' ejecutado. Salida: $salida"
                        }
                    }
                   "WIPE" {
                        try {
                            # 1. Capturamos la instancia real del equipo
                            $WipeInstance = Get-CimInstance -Namespace "root\cimv2\mdm\dmmap" -ClassName "MDM_RemoteWipe" -ErrorAction Stop
                            
                            if ($WipeInstance) {
                                # 2. Le enviamos la orden a esa instancia CON el parÃ¡metro vacÃ­o que exige Microsoft
                                Invoke-CimMethod -InputObject $WipeInstance -MethodName "doWipeMethod" -Arguments @{param=""} -ErrorAction Stop
                                $detalle_error = "WIPE INICIADO CON Ã‰XITO. El equipo se reiniciarÃ¡ para el borrado de fÃ¡brica."
                            } else {
                                $resultado = "FAILED"
                                $detalle_error = "No se pudo iniciar WIPE: La clase MDM_RemoteWipe no estÃ¡ disponible."
                            }
                        } catch {
                            $resultado = "FAILED"
                            $detalle_error = "Error crÃ­tico al ejecutar WIPE: $($_.Exception.Message)"
                        }
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

if ($Once) {
    Send-Sync
} else {
    try {
        $seguidas = 0
        while ($true) {
            Send-Sync

            # Vaciar la cola. El servidor entrega una orden por peticion, asi
            # que si acaba de ejecutarse una lo normal es que haya mas detras:
            # antes, tres ordenes eran quince minutos. El tope de 10 es un
            # seguro; una orden entregada pasa a SENT y no puede volver a
            # salir, pero no cuesta nada tenerlo.
            if ($script:OrdenEjecutada -and $seguidas -lt 10) {
                $seguidas++
                continue
            }
            $seguidas = 0

            # La espera, a trocitos. En cada trocito se hace la pregunta barata;
            # si hay algo en cola se corta y el Send-Sync de arriba lo recoge
            # por el camino de siempre. El inventario completo se sigue mandando
            # cada $IntervaloInventario, igual que antes.
            $esperado = 0
            while ($esperado -lt $IntervaloInventario) {
                Start-Sleep -Seconds $IntervaloSondeo
                $esperado += $IntervaloSondeo
                if (Test-HayOrden) { break }
            }
        }
    } catch {
        Write-MDMAuditLog -Accion "Parada de Agente" -Detalles "El bucle principal del agente $Version ha terminado por un error: $($_.Exception.Message)" -EventID 1005
    } finally {
        Write-MDMAuditLog -Accion "Parada de Agente" -Detalles "El agente $Version deja de ejecutarse." -EventID 1005
    }
}
"""

LINUX_AGENT_CODE = r"""import os, json, time, socket, urllib.request, ssl, subprocess
API_URL = "https://gmdm.gigas.com:8443"
TOKEN = "{{AGENT_TOKEN}}"
VERSION = "v7.1.0-Linux"
ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return res.stdout.strip(), res.stderr.strip(), res.returncode
    except Exception as e: return "", str(e), 1

def _campos_lsblk(linea):
    # Parte una linea de 'lsblk -P' (NAME="x" FSTYPE="y") en un diccionario.
    datos = {}
    for trozo in linea.strip().split('" '):
        if "=" in trozo:
            clave, valor = trozo.split("=", 1)
            datos[clave.strip()] = valor.strip().strip('"')
    return datos

def _luks_dispositivos():
    # Lista los dispositivos con cabecera LUKS, comprobados uno a uno.
    #
    # No se da por hecho ningun /dev/sdaN: se pregunta al sistema y despues se
    # confirma con 'cryptsetup isLuks', que lee la cabecera de verdad.
    candidatos = []
    out, _e, _c = run_cmd("lsblk -P -p -o NAME,FSTYPE")
    for linea in out.splitlines():
        datos = _campos_lsblk(linea)
        if datos.get("FSTYPE", "") == "crypto_LUKS" and datos.get("NAME"):
            candidatos.append(datos["NAME"])
    if not candidatos:
        out, _e, _c = run_cmd("blkid -t TYPE=crypto_LUKS -o device")
        candidatos = [l.strip() for l in out.splitlines() if l.strip()]
    vistos, reales = set(), []
    for dev in candidatos:
        if dev in vistos:
            continue
        vistos.add(dev)
        _o, _e, code = run_cmd("cryptsetup isLuks " + dev)
        if code == 0:
            reales.append(dev)
    return reales

def _luks_slots(dev):
    # Cuenta los slots de clave activos releyendo la cabecera del disco.
    #
    # Devuelve (slots, version, fallo). slots = -1 si la cabecera no se puede
    # leer, que despues del borrado es buena noticia y antes es motivo de parar.
    out, err, code = run_cmd("cryptsetup luksDump " + dev)
    if code != 0:
        return -1, "?", (err.splitlines()[0] if err else "luksDump devolvio " + str(code))
    version = "?"
    for linea in out.splitlines():
        if linea.strip().startswith("Version:"):
            version = linea.split(":", 1)[1].strip()
            break
    activos = 0
    if version == "1":
        for linea in out.splitlines():
            if linea.strip().startswith("Key Slot") and "ENABLED" in linea:
                activos += 1
    else:
        dentro = False
        for linea in out.splitlines():
            if linea.startswith("Keyslots:"):
                dentro = True
                continue
            if not dentro:
                continue
            if not linea.strip():
                continue
            if not linea.startswith((" ", "\t")):
                break
            trozos = linea.strip().split(":")
            if len(trozos) >= 2 and trozos[0].strip().isdigit() and trozos[1].strip().startswith("luks"):
                activos += 1
    return activos, version, ""

def _slots_txt(n, verbo=False):
    # '1 slot activo' / '3 slots activos', para que el parte del panel no cante.
    if verbo:
        return ("borrado 1 slot" if n == 1 else "borrados %d slots" % n)
    return ("1 slot activo" if n == 1 else "%d slots activos" % n)

def _luks_papel(dev):
    # Dice si de ese LUKS cuelga la raiz del sistema y donde esta montado.
    #
    # No sabiamos si en el parque se cifra el disco entero o un volumen de datos
    # aparte, asi que lo mira el propio equipo y lo cuenta en el resultado.
    puntos = []
    out, _e, _c = run_cmd("lsblk -P -p -o NAME,TYPE,MOUNTPOINT " + dev)
    for linea in out.splitlines():
        datos = _campos_lsblk(linea)
        punto = datos.get("MOUNTPOINT", "") or datos.get("MOUNTPOINTS", "")
        if punto:
            puntos.append(punto)
    papel = "disco del sistema" if "/" in puntos else "volumen de datos"
    return papel, puntos

def _programar_apagado(segundos):
    # Apaga el equipo con retraso, para que al panel le de tiempo a recibir el parte.
    #
    # Apagar, no reiniciar: reiniciar solo lleva a una pantalla pidiendo una
    # contrasena que ya no abre nada. Y hay prisa, porque mientras el equipo
    # siga encendido la clave maestra sigue en la memoria del kernel y los
    # discos ya abiertos se leen igual que antes.
    orden = "systemd-run --on-active=%d --unit=gmdm-wipe-apagado /bin/sh -c 'poweroff -f'" % segundos
    _o, _e, code = run_cmd(orden)
    if code == 0:
        return "el equipo se apaga en %d segundos" % segundos
    _o, _e, code = run_cmd("nohup sh -c 'sleep %d; poweroff -f || systemctl poweroff --force' >/dev/null 2>&1 &" % segundos)
    if code == 0:
        return "el equipo se apaga en %d segundos (sin systemd-run)" % segundos
    return ("AVISO: no se ha podido programar el apagado. Hay que apagarlo a mano: "
            "mientras siga encendido la clave maestra esta en memoria")

def wipe_luks(param):
    # Borrado remoto en Linux por borrado criptografico (cryptsetup luksErase).
    #
    # Lo que habia antes era 'rm -rf --no-preserve-root / &' y tenia cuatro
    # defectos: no borraba (rm desenlaza, los datos siguen en el disco); sin -x
    # bajaba por todo lo montado y se llevaba por delante un NAS colgado de
    # /mnt; el & devolvia "WIPE INICIADO" sin mirar nada, el enesimo exito
    # fingido; y no apagaba, dejaba el equipo a medio destruir.
    #
    # Aqui se borran los slots de clave de la cabecera LUKS. Sin slots no hay
    # forma de derivar la clave maestra, ni con la contrasena correcta: el disco
    # entero queda ilegible. Es irreversible y en el parque no se guarda copia
    # de la cabecera en ningun sitio.
    #
    # Con parametro 'simular' no borra nada: solo cuenta lo que encontraria.
    simular = (param or "").strip().lower() in ("simular", "simulacion", "diagnostico", "dry", "dry-run")

    _o, _e, code = run_cmd("command -v cryptsetup")
    if code != 0:
        return "FAILED", ("No hay cryptsetup en este equipo, asi que no se puede hacer el "
                          "borrado criptografico. No se ha tocado nada.")

    dispositivos = _luks_dispositivos()
    if not dispositivos:
        return "FAILED", ("No se ha encontrado ninguna cabecera LUKS. El borrado remoto de "
                          "Linux solo sabe hacer borrado criptografico y este equipo no esta "
                          "cifrado: no se ha borrado nada. Hay que retirarlo a mano.")

    inventario = []
    for dev in dispositivos:
        slots, version, fallo = _luks_slots(dev)
        papel, puntos = _luks_papel(dev)
        inventario.append({"dev": dev, "slots": slots, "version": version,
                           "fallo": fallo, "papel": papel, "puntos": puntos})

    encontrado = "; ".join(
        "%s (LUKS%s, %s%s): %s" % (
            i["dev"], i["version"], i["papel"],
            ", montado en " + " ".join(i["puntos"]) if i["puntos"] else ", sin montar",
            _slots_txt(i["slots"]) if i["slots"] >= 0 else ("cabecera ilegible: " + i["fallo"]))
        for i in inventario)

    if simular:
        return "SUCCESS", "SIMULACION, no se ha borrado nada. Encontrado: " + encontrado + "."

    hechos, fallidos = [], []
    for i in inventario:
        dev = i["dev"]
        if i["slots"] < 0:
            fallidos.append("%s: no se ha podido leer la cabecera (%s), no se toca" % (dev, i["fallo"]))
            continue
        if i["slots"] == 0:
            hechos.append("%s (%s): ya no tenia ningun slot activo" % (dev, i["papel"]))
            continue
        _o, err, _c = run_cmd("cryptsetup luksErase --batch-mode " + dev)
        quedan, _v, _f = _luks_slots(dev)
        if quedan == 0:
            hechos.append("%s (%s, LUKS%s): %s, cabecera releida sin ninguno"
                          % (dev, i["papel"], i["version"], _slots_txt(i["slots"], True)))
        elif quedan < 0:
            _o2, _e2, code2 = run_cmd("cryptsetup isLuks " + dev)
            if code2 != 0:
                hechos.append("%s (%s): la cabecera ya ni se reconoce como LUKS" % (dev, i["papel"]))
            else:
                fallidos.append("%s: no se ha podido releer la cabecera para comprobarlo" % dev)
        else:
            fallidos.append("%s: despues de luksErase la cabecera aun tiene %s (%s)"
                            % (dev, _slots_txt(quedan), err.splitlines()[0] if err else "sin error"))

    if not hechos:
        return "FAILED", "No se ha borrado ninguna clave. " + " | ".join(fallidos) + ". El equipo sigue encendido."

    apagado = _programar_apagado(30)
    detalle = "Borrado criptografico: " + " | ".join(hechos) + ". " + apagado + "."
    if fallidos:
        return "FAILED", ("BORRADO A MEDIAS. " + detalle + " SIN BORRAR: " + " | ".join(fallidos)
                          + ". Lo que no se ha borrado sigue siendo descifrable con su contrasena.")
    return "SUCCESS", detalle

def get_inventory():
    hostname = socket.gethostname()
    try:
        if "microsoft" in open("/proc/version").read().lower():
            hostname += "-WSL"
    except: pass

    os_name = "Linux"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="): os_name = line.split("=")[1].strip().strip('"')
    except: pass
    out, _, _ = run_cmd("uptime -p")
    uptime = out.replace("up ", "") if out else "N/D"
    out, _, _ = run_cmd("free -m | awk '/^Mem:/{print $2}'")
    ram = f"{round(int(out)/1024, 2)} GB" if out.isdigit() else "N/D"
    out, _, _ = run_cmd("df -h / | tail -1 | awk '{print $4 \" libres de \" $2}'")
    disco = out if out else "N/D"
    ip_local = mac = "N/D"
    try:
        ip_local = run_cmd("ip -4 route get 1.1.1.1 | awk '{print $7}'")[0]
        if ip_local: mac = run_cmd("ip link show | awk '/ether/ {print $2}'")[0].split('\n')[0]
    except: pass
    usuario = run_cmd("who | awk '{print $1}' | head -1")[0] or "root"
    sw_out, _, _ = run_cmd("dpkg-query -W -f='${Package} (${Version})||'")
    luks, _, _ = run_cmd("lsblk -f | grep crypto_LUKS")
    return {"hostname": hostname, "usuario": usuario, "os": os_name, "ram": ram, "disco": disco, "ip_local": ip_local, "ip_publica": "N/D", "mac": mac, "bitlocker": "Ã°Å¸Å¸Â¢ Cifrado (LUKS)" if luks else "Ã°Å¸â€Â´ Desprotegido", "antivirus": "N/D", "software": sw_out.strip('||') if sw_out else "", "kbs": "", "agente": VERSION, "uptime": uptime}

def send_callback(cmd_id, estado, detalle):
    req = urllib.request.Request(f"{API_URL}/api/callback", data=json.dumps({"id": cmd_id, "estado": estado, "detalle": detalle}).encode('utf-8'), headers={'Content-Type': 'application/json', 'X-Auth-Token': TOKEN}, method='POST')
    try: urllib.request.urlopen(req, context=ssl_ctx, timeout=10)
    except: pass

def sync():
    req = urllib.request.Request(f"{API_URL}/sync", data=json.dumps(get_inventory()).encode('utf-8'), headers={'Content-Type': 'application/json', 'X-Auth-Token': TOKEN}, method='POST')
    try:
        res_data = json.loads(urllib.request.urlopen(req, context=ssl_ctx, timeout=15).read().decode('utf-8'))
        if res_data.get("status") == "command":
            cmd, param, estado, detalle = res_data.get("comando"), res_data.get("parametro", ""), "SUCCESS", ""
            if cmd == "UPDATE_AGENT":
                out, err, code = run_cmd(f"curl -s -k -H 'X-Auth-Token: {TOKEN}' https://gmdm.gigas.com:8443/agent_code_linux -o /opt/gmdm_agent/gmdm_agent.py && systemctl restart gmdm-agent.service")
                if code == 0: detalle = "Agente Linux actualizado a v7.0.3-Linux correctamente."
                else: estado, detalle = "FAILED", f"Error actualizando: {err}"
            elif cmd == "REBOOT": run_cmd("reboot"); detalle = "Reinicio forzado."
            elif cmd == "SHUTDOWN": run_cmd("shutdown -h now"); detalle = "Apagado forzado."
            elif cmd == "SEND_MESSAGE": run_cmd(f"wall '{param}'"); detalle = "Mensaje enviado."
            elif cmd == "CREATE_IT_USER":
                # Parametro: usuario||contrasena||horas (parche 17). Antes era
                # solo el nombre y se metia crudo en una shell: con el formato
                # nuevo, "usuario||loquesea" habria ejecutado la segunda parte
                # como una orden mas.
                trozos = (param or "").split("||")
                usr = trozos[0].strip() or "AdminIT_Temp"
                clave, texto_horas = "", ""
                if len(trozos) >= 3: clave, texto_horas = "||".join(trozos[1:-1]), trozos[-1].strip()
                elif len(trozos) == 2: clave = trozos[1]
                if not clave.strip(): clave = "Temporal_2026!"
                try: horas = float(texto_horas.replace(",", ".") or 0)
                except ValueError: horas = 0.0
                if not usr[0].isalpha() or not all(ch.isalnum() or ch in "._-" for ch in usr):
                    estado, detalle = "FAILED", f"Nombre de usuario no valido: {usr}"
                elif "\n" in clave or "\r" in clave:
                    estado, detalle = "FAILED", "La contrasena no puede llevar saltos de linea: chpasswd lee una pareja por linea."
                elif horas > 8760:
                    estado, detalle = "FAILED", f"Caducidad no valida: {horas} horas. El maximo es 8760."
                else:
                    out, err, code = run_cmd(f"useradd -m -s /bin/bash {usr}")
                    if code != 0: estado, detalle = "FAILED", err or f"useradd devolvio {code}"
                    else:
                        # La contrasena NO pasa por la shell: en un "echo x:y | chpasswd"
                        # la ve entera cualquiera que mire la tabla de procesos.
                        try:
                            r = subprocess.run(["chpasswd"], input=f"{usr}:{clave}\n", text=True, capture_output=True, timeout=60)
                            code, err = r.returncode, r.stderr.strip()
                        except Exception as e: code, err = 1, str(e)
                    if estado == "SUCCESS" and code != 0:
                        run_cmd(f"userdel -r -f {usr}")
                        estado, detalle = "FAILED", f"No se pudo poner la contrasena ({err}). La cuenta se ha deshecho."
                    elif estado == "SUCCESS":
                        caducidad = "sin caducidad"
                        if horas > 0:
                            # usermod -e siempre, aunque solo tenga granularidad de dia:
                            # el timer de systemd-run es transitorio y se pierde al
                            # reiniciar, asi que por si solo no garantiza nada.
                            fecha = time.strftime("%Y-%m-%d", time.localtime(time.time() + horas * 3600 + 86400))
                            run_cmd(f"usermod -e {fecha} {usr}")
                            _o, _e, c2 = run_cmd(f"systemd-run --on-active={int(horas * 3600)} --unit=gmdm-borrar-{usr} /usr/sbin/userdel -r -f {usr}")
                            if c2 == 0: caducidad = f"se borra sola dentro de {horas} h, y la cuenta caduca el {fecha}"
                            else: caducidad = f"sin systemd-run: no se borra sola, solo caduca el {fecha} (granularidad de dia)"
                        detalle = f"Usuario {usr} creado, {caducidad}. No se le ha dado sudo. La contrasena es la del panel y no queda registrada."
            elif cmd == "DESTROY_IT_USER":
                usr = (param or "").split("||")[0].strip() or "AdminIT_Temp"
                if usr in ("root", "daemon", "bin", "sys", "sync", "ubuntu", "debian", "admin"):
                    estado, detalle = "FAILED", f"La cuenta {usr} esta protegida y no se elimina desde el panel."
                elif not usr[0].isalpha() or not all(ch.isalnum() or ch in "._-" for ch in usr):
                    estado, detalle = "FAILED", f"Nombre de usuario no valido: {usr}"
                else:
                    run_cmd(f"systemctl stop gmdm-borrar-{usr}.timer")
                    out, err, code = run_cmd(f"userdel -r {usr}")
                    if code == 0: detalle = f"Usuario {usr} eliminado."
                    else: estado, detalle = "FAILED", err or f"userdel devolvio {code}"
            elif cmd == "ENABLE_RDP": run_cmd("systemctl start ssh && systemctl enable ssh"); detalle = "SSH habilitado."
            elif cmd == "DISABLE_RDP": run_cmd("systemctl stop ssh && systemctl disable ssh"); detalle = "SSH deshabilitado."
            elif cmd == "OS_PATCHES":
                out, err, code = run_cmd("DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y")
                if code == 0: detalle = "Actualizacion APT completada."
                else: estado, detalle = "FAILED", err
            elif cmd == "TEMP_ADMIN":
                # El panel manda "usuario||horas" tambien a los Linux. Se pasaba
                # la cadena entera a usermod dentro de un shell: ni funcionaba ni
                # era seguro. Se parte, se valida el nombre contra una lista de
                # caracteres permitidos y se comprueba el resultado con id -nG.
                validos = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
                usuario = (param or "").split("||")[0].strip()
                if not usuario or not set(usuario) <= validos:
                    estado, detalle = "FAILED", f"Nombre de usuario no valido: '{usuario}'."
                else:
                    out, err, code = run_cmd(f"usermod -aG sudo {usuario}")
                    if code != 0:
                        estado, detalle = "FAILED", err or "usermod ha devuelto error."
                    else:
                        grupos, _, _ = run_cmd(f"id -nG {usuario}")
                        if "sudo" not in grupos.split():
                            estado, detalle = "FAILED", f"{usuario} no aparece en el grupo sudo despues de usermod."
                        else:
                            detalle = f"Sudo concedido a {usuario}. AVISO: en Linux no hay revocacion automatica, hay que lanzar REVOKE_ADMIN a mano."
            elif cmd == "REVOKE_ADMIN":
                validos = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
                usuario = (param or "").split("||")[0].strip()
                if not usuario or not set(usuario) <= validos:
                    estado, detalle = "FAILED", f"Nombre de usuario no valido: '{usuario}'."
                else:
                    out, err, code = run_cmd(f"deluser {usuario} sudo")
                    grupos, _, _ = run_cmd(f"id -nG {usuario}")
                    if "sudo" in grupos.split():
                        estado, detalle = "FAILED", f"{usuario} sigue perteneciendo al grupo sudo."
                    else:
                        detalle = f"Sudo retirado a {usuario}."
            elif cmd == "INSTALL_SW":
                out, err, code = run_cmd(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {param}")
                if code == 0: detalle = f"Instalado {param}."
                else: estado, detalle = "FAILED", err
            elif cmd == "UNINSTALL_SW":
                out, err, code = run_cmd(f"DEBIAN_FRONTEND=noninteractive apt-get purge -y {param}")
                if code == 0: detalle = f"Eliminado {param}."
                else: estado, detalle = "FAILED", err
            elif cmd == "CUSTOM_PS1":
                # El panel solo admite subir .ps1, que es PowerShell de
                # Windows. Antes se pasaba el nombre del fichero a la shell
                # y fallaba con un "command not found" confuso. Mejor decir
                # la verdad que aparentar que se ha intentado algo.
                estado = "FAILED"
                detalle = ("Este equipo es Linux y los scripts del panel son .ps1 "
                           "de Windows. No se ha ejecutado nada.")
            elif cmd == "WIPE":
                # Borrado criptografico, no "rm -rf /": ver wipe_luks() arriba.
                # El estado sale de ahi, no es fijo, y el equipo se apaga solo
                # a los 30 segundos para que este parte llegue antes.
                estado, detalle = wipe_luks(param)
            else: estado, detalle = "FAILED", "Comando no aplicable en Linux."
            send_callback(res_data.get("id"), estado, detalle)
    except Exception: pass

if __name__ == "__main__":
    while True:
        sync()
        time.sleep(300)
"""

def _autorizado_para_agente():
    """Deja pasar al agente o a un administrador del panel, a nadie mas.

    Estas rutas devuelven el codigo del agente con AGENT_TOKEN y
    TEMP_ADMIN_PWD ya sustituidos dentro. Estaban completamente abiertas:
    cualquiera que alcanzara el puerto 8443 se llevaba las dos credenciales en
    claro sin necesidad de identificarse.

    Cerrarlas no rompe el parque instalado, porque los agentes ya mandaban la
    cabecera X-Auth-Token al autoactualizarse. El unico que iba sin ella era el
    script de arranque de los Linux, corregido aqui mismo.
    """
    if request.headers.get('X-Auth-Token') in TOKENS_AGENTE:
        return True

    es_valido, email, rol = validar_login_google(request.args.get('token'))
    if es_valido and rol == "ADMIN":
        logging.info("DESCARGA AGENTE | ADMIN: %s | RUTA: %s"
                     % (email, request.path))
        return True

    logging.warning("DESCARGA AGENTE RECHAZADA | IP: %s | RUTA: %s"
                    % (request.remote_addr, request.path))
    return False


@app.route('/deploy', methods=['GET'])
@app.route('/agent_code', methods=['GET'])
def deploy_agent():
    if not _autorizado_para_agente():
        return jsonify({"status": "error", "msg": "Acceso denegado"}), 403
    agent_script = AGENT_CODE.replace('{{AGENT_TOKEN}}', AGENT_TOKEN).replace('{{TEMP_ADMIN_PWD}}', TEMP_ADMIN_PWD)
    response = make_response(agent_script)
    response.headers["Content-Disposition"] = "attachment; filename=microagente.ps1"
    response.headers["Content-type"] = "text/plain"
    return response

@app.route('/deploy_linux', methods=['GET'])
def deploy_linux_script():
    if not _autorizado_para_agente():
        return make_response("Acceso denegado\n", 403, {"Content-type": "text/plain"})
    # El curl de aqui dentro descargaba el agente sin cabecera ninguna. Ahora
    # se le inyecta el token, porque /agent_code_linux ya no esta abierto.
    bash_script = """#!/bin/bash
mkdir -p /opt/gmdm_agent
curl -s -k -H "X-Auth-Token: {{AGENT_TOKEN}}" https://gmdm.gigas.com:8443/agent_code_linux -o /opt/gmdm_agent/gmdm_agent.py
cat << 'EOF' > /etc/systemd/system/gmdm-agent.service
[Unit]
Description=Gigas MDM Linux Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/gmdm_agent
ExecStart=/usr/bin/python3 /opt/gmdm_agent/gmdm_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
chmod 600 /opt/gmdm_agent/gmdm_agent.py
systemctl daemon-reload
systemctl enable gmdm-agent.service --now
systemctl restart gmdm-agent.service
echo "Agente Linux instalado correctamente y reportando a panel web."
"""
    return make_response(bash_script.replace('{{AGENT_TOKEN}}', AGENT_TOKEN),
                         200, {"Content-type": "text/plain"})

@app.route('/agent_code_linux', methods=['GET'])
def deploy_linux_python():
    if not _autorizado_para_agente():
        return make_response("Acceso denegado\n", 403, {"Content-type": "text/plain"})
    return make_response(LINUX_AGENT_CODE.replace('{{AGENT_TOKEN}}', AGENT_TOKEN), 200, {"Content-type": "text/plain"})

@app.route('/sync', methods=['POST'])
def sync():
    if request.headers.get('X-Auth-Token') not in TOKENS_AGENTE:
        return jsonify({"status": "error", "msg": "Unauthorized"}), 401

    data = request.json
    hostname = data.get('hostname')
    if not hostname: return jsonify({"status": "error"}), 400
        
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    software_db = format_to_pipes(data.get('software', ''), 'software')
    kbs_db = format_to_pipes(data.get('kbs', ''), 'kbs')
    kbs_pendientes_db = format_to_pipes(data.get('kbs_pendientes', ''), 'kbs')
    
    antivirus = data.get('antivirus', 'N/D')
    uptime = data.get('uptime', 'N/D')

    ip_conexion_proxy = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    ip_publica_agente = data.get('ip_publica', 'N/D')
    ip_publica_final = ip_conexion_proxy if (not ip_publica_agente or ip_publica_agente == 'N/D') else ip_publica_agente

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO agents (
            hostname, usuario, serial, os, ram, disco, ip_local, ip_publica, mac, bitlocker, antivirus, software, kbs, kbs_pendientes, agente, ultima_conexion, uptime
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            usuario=VALUES(usuario), serial=VALUES(serial), os=VALUES(os),
            ram=VALUES(ram), disco=VALUES(disco), ip_local=VALUES(ip_local),
            ip_publica=VALUES(ip_publica), mac=VALUES(mac), bitlocker=VALUES(bitlocker),
            antivirus=VALUES(antivirus), software=VALUES(software), kbs=VALUES(kbs),
            kbs_pendientes=VALUES(kbs_pendientes),
            agente=VALUES(agente), ultima_conexion=VALUES(ultima_conexion), uptime=VALUES(uptime)
    ''', (
        hostname, data.get('usuario', ''), data.get('serial', ''), data.get('os', ''),
        data.get('ram', ''), data.get('disco', ''), data.get('ip_local', ''),
        ip_publica_final, data.get('mac', ''), data.get('bitlocker', ''),
        antivirus, software_db, kbs_db, kbs_pendientes_db, data.get('agente', ''), now, uptime
    ))
    
    c.execute("SELECT id, comando, parametro FROM command_queue WHERE hostname=%s AND estado='PENDING' LIMIT 1", (hostname,))
    cmd = c.fetchone()
    
    if cmd:
        c.execute("UPDATE command_queue SET estado='SENT' WHERE id=%s", (cmd['id'],))
        # La contrasena de una orden de creacion de cuenta viaja al equipo una
        # sola vez. En cuanto la orden sale de la cola se borra de la fila,
        # para que no se quede en la base de datos en claro despues de haberse
        # usado (parche 17).
        if cmd['comando'] in COMANDOS_CON_SECRETO:
            c.execute("UPDATE command_queue SET parametro=%s WHERE id=%s",
                      (_parametro_sin_secreto(cmd['comando'], cmd['parametro']), cmd['id']))
        conn.close()
        return jsonify({"status": "command", "id": cmd['id'], "comando": cmd['comando'], "parametro": cmd['parametro']})
        
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/api/hay-orden', methods=['GET'])
def hay_orden():
    """Sondeo ligero del agente (parche 22).

    Dice si el equipo tiene algo esperando en la cola, y nada mas. NO entrega
    la orden ni la marca como SENT: de eso sigue encargandose /sync, que es el
    unico sitio donde una orden sale de la cola. Asi no hay dos caminos de
    entrega que puedan acabar divergiendo.

    Es deliberadamente barato: una lectura sobre command_queue, sin tocar la
    tabla agents y sin salir a internet. El agente lo llama cada 20 segundos
    para no tener que esperar los 300 del inventario completo.
    """
    if request.headers.get('X-Auth-Token') not in TOKENS_AGENTE:
        return jsonify({"status": "error", "msg": "Unauthorized"}), 401

    hostname = request.args.get('hostname', '')
    if not hostname:
        return jsonify({"status": "error"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM command_queue WHERE hostname=%s AND estado='PENDING' LIMIT 1", (hostname,))
    hay = c.fetchone() is not None
    conn.close()

    return jsonify({"hay": hay})

@app.route('/api/callback', methods=['POST'])
def command_callback():
    if request.headers.get('X-Auth-Token') not in TOKENS_AGENTE:
        return jsonify({"status": "error", "msg": "Unauthorized"}), 401

    data = request.json
    cmd_id = data.get('id')
    estado = data.get('estado')
    detalle = data.get('detalle', '')

    if not cmd_id or not estado: return jsonify({"status": "error"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE command_queue SET estado=%s, detalle_resultado=%s WHERE id=%s", (estado, detalle, cmd_id))
    
    c.execute("SELECT hostname, comando FROM command_queue WHERE id=%s", (cmd_id,))
    cmd_info = c.fetchone()
    
    if cmd_info:
        nombre_humano = NOMBRES_ACCIONES.get(cmd_info['comando'], cmd_info['comando'])
        register_audit_action(cmd_info['hostname'], "SYSTEM (Agente)", cmd_info['comando'], estado, f"Resultado de {nombre_humano}: {detalle}")
        
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/session/start', methods=['POST'])
def session_start():
    data = request.json or {}
    # Contra Google directamente: una sesion no puede servir para fabricar otra.
    es_valido, email, rol = validar_id_token_google(data.get('token'))
    if not es_valido:
        return jsonify({"status": "error", "msg": "Acceso denegado"}), 403
 
    caduca = int(time.time()) + GMDM_SESSION_TTL
    register_audit_action("-", email, "LOGIN", "OK", "Sesion de panel iniciada")
    return jsonify({
        "status": "ok",
        "sesion": _firmar_sesion(email, rol, caduca),
        "email": email,
        "rol": rol,
        "caduca": caduca
    })
 
 


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
    register_audit_action(hostname, email, comando, "QUEUED", f"Orden: {nombre_humano} | Parametro: {_parametro_sin_secreto(comando, parametro)}")
    return jsonify({"status": "ok", "msg": f"Comando '{nombre_humano}' encolado."})

@app.route('/get_inventory', methods=['GET'])
def get_inventory():
    token = request.args.get('token')
    es_valido, email, rol = validar_login_google(token)
    if not es_valido: return jsonify({"status": "error"}), 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT hostname, usuario, serial, os, ram, disco, ip_local, ip_publica, mac, bitlocker, antivirus, uptime, software, kbs, agente, DATE_FORMAT(ultima_conexion, '%Y-%m-%d %H:%i:%s') AS ultima_conexion, DATE_FORMAT(fecha_insercion, '%Y-%m-%d %H:%i:%s') AS fecha_insercion FROM agents ORDER BY ultima_conexion DESC")
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
    if not es_valido or rol != "ADMIN": return jsonify({"status": "error", "msg": "Acceso denegado"}), 403

    if 'scripts' not in request.files: return jsonify({"status": "error"}), 400

    archivos = request.files.getlist('scripts')
    for file in archivos:
        if file.filename.endswith('.ps1'):
            safe_filename = secure_filename(file.filename)
            filepath = os.path.join(SCRIPTS_DIR, safe_filename)
            file.save(filepath)
            register_audit_action("SERVER", email, "UPLOAD_SCRIPT", "SUCCESS", safe_filename)

    return jsonify({"status": "ok", "msg": "Scripts subidos."})

@app.route('/get_script_content', methods=['GET'])
def get_script_content():
    """Entrega al agente el contenido de un .ps1 subido desde el panel.

    Esta ruta faltaba, y era el motivo por el que "Lanzar Script en Lote" no
    hizo nunca nada util: /upload_scripts guardaba el fichero aqui en el
    servidor, el panel mandaba el nombre al equipo, y el equipo lo buscaba en
    su carpeta local del agente, donde no habia llegado nunca.

    Cerrada igual que las rutas del agente: cabecera X-Auth-Token de agente, o
    sesion de ADMIN del panel para poder comprobarla a mano desde el navegador.
    """
    if not _autorizado_para_agente():
        return jsonify({"status": "error", "msg": "Acceso denegado"}), 403

    nombre = secure_filename(request.args.get('nombre', ''))
    if not nombre.lower().endswith('.ps1'):
        return jsonify({"status": "error",
                        "msg": "Solo se sirven ficheros .ps1"}), 400

    ruta = os.path.join(SCRIPTS_DIR, nombre)
    if not os.path.isfile(ruta):
        logging.warning("SCRIPT NO ENCONTRADO | %s | IP: %s"
                        % (nombre, request.remote_addr))
        return jsonify({"status": "error",
                        "msg": "No existe el script " + nombre}), 404

    with open(ruta, 'rb') as f:
        contenido = f.read()

    logging.info("ENTREGA SCRIPT | %s | %d bytes | IP: %s"
                 % (nombre, len(contenido), request.remote_addr))

    respuesta = make_response(contenido)
    respuesta.headers['Content-Type'] = 'text/plain; charset=utf-8'
    return respuesta


@app.route('/get_scripts', methods=['GET'])
def get_scripts():
    token = request.args.get('token')
    es_valido, email, rol = validar_login_google(token)
    if not es_valido: return jsonify({"status": "error"}), 403

    scripts = [f for f in os.listdir(SCRIPTS_DIR) if f.lower().endswith('.ps1')] if os.path.exists(SCRIPTS_DIR) else []
    return jsonify({"status": "ok", "scripts": sorted(scripts)})

@app.route('/api/stats/os', methods=['GET'])
def get_os_stats():
    es_valido, email, rol = validar_login_google(request.args.get('token'))
    if not es_valido:
        return jsonify({"status": "error", "msg": "Acceso denegado"}), 403
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT os, COUNT(*) as total FROM agents GROUP BY os")
    rows = c.fetchall()
    conn.close()
    return jsonify({row['os']: row['total'] for row in rows if row['os']})

@app.route('/api/heartbeat', methods=['POST'])
def linux_heartbeat():
    token = request.headers.get('X-Auth-Token')
    if token not in TOKENS_AGENTE:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    if not data:
        return jsonify({"error": "Bad Request"}), 400

    hostname = data.get('hostname')
    if not hostname:
        return jsonify({"error": "Missing hostname"}), 400

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
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
            'N/D',                     
            data.get('os', 'Linux'),  
            'N/D',                     
            'N/D',                     
            data.get('ip_local', 'N/D'),
            ip_publica_final, 
            'N/D',                     
            'N/D',                     
            'N/D',                     
            '',                        
            '',                        
            data.get('version', 'N/D'), 
            now,
            'N/D',                     
            data.get('ubicacion', 'Desconocida')
        ))
        
        conn.commit()
        
    except Exception as e:
        conn.close()
        return jsonify({"error": "DB insert failed", "details": str(e)}), 500

    conn.close()
    return jsonify({"status": "ok", "message": "Heartbeat Linux registrado con ubicacion"})

@app.route('/delete_agent', methods=['POST'])
def delete_agent():
    data = request.json
    token = data.get('token')
    es_valido, email, rol = validar_login_google(token)
    if not es_valido or rol != "ADMIN": 
        return jsonify({"status": "error", "msg": "Acceso denegado"}), 403

    hostname = data.get('hostname')
    if not hostname: 
        return jsonify({"status": "error", "msg": "Hostname requerido"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM agents WHERE hostname = %s", (hostname,))
    c.execute("DELETE FROM command_queue WHERE hostname = %s", (hostname,))
    conn.close()

    register_audit_action("SERVER", email, "DELETE_AGENT", "SUCCESS", f"Equipo {hostname} eliminado del panel.")
    
    return jsonify({"status": "ok", "msg": f"Equipo {hostname} eliminado."})

@app.route('/api/patches/pending', methods=['GET'])
def get_pending_patches():
    token = request.args.get('token')
    es_valido, email, rol = validar_login_google(token)
    if not es_valido: return jsonify({"status": "error"}), 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT hostname, kbs_pendientes FROM agents WHERE kbs_pendientes IS NOT NULL AND kbs_pendientes != ''")
    equipos = c.fetchall()
    conn.close()

    # Parche 26: cada elemento llega como "KB123::titulo" (agente v6.9.32 o
    # posterior) o como "KB123" (agentes anteriores). Se agrupa por numero.
    kbs_agrupados = {}
    titulos = {}
    for eq in equipos:
        if eq['kbs_pendientes']:
            lista_kbs = eq['kbs_pendientes'].split('||')
            for elemento in lista_kbs:
                kb, _, titulo = elemento.partition('::')
                kb = kb.strip()
                titulo = titulo.strip()
                if not kb: continue
                if kb not in kbs_agrupados:
                    kbs_agrupados[kb] = []
                if eq['hostname'] not in kbs_agrupados[kb]:
                    kbs_agrupados[kb].append(eq['hostname'])
                if titulo and not titulos.get(kb):
                    titulos[kb] = titulo

    conn = get_db_connection()
    c = conn.cursor()
    resultado = []
    for kb, hosts in kbs_agrupados.items():
        numero = normalizar_kb(kb)
        est = leer_estado_kb(c, numero) if numero else None
        resultado.append({
            "kb": kb,
            "descripcion": titulos.get(kb) or "Sin titulo: ningun equipo con este KB tiene aun el agente v6.9.32",
            "equipos": hosts,
            "total": len(hosts),
            "estado": est["estado"] if est else "PENDIENTE",
            "motivo": est["motivo"] if est else "",
            "revision_vencida": est["revision_vencida"] if est else False
        })
    conn.close()
    resultado.sort(key=lambda r: (-r["total"], r["kb"]))

    return jsonify({"status": "ok", "data": resultado})

# ---------------------------------------------------------------------------
# Gobierno de parches (seccion 9 de PATCH-GMDM.md)
#
# Aqui habia dos analizadores y los dos se inventaban el veredicto. El primero
# miraba si el numero de la KB acababa en 5. El segundo preguntaba a un modelo
# sin acceso a internet, con una clave que era un marcador de posicion, y
# cuando fallaba escupia el KeyError por la interfaz como si fuera una
# recomendacion. Los dos daban por bueno un parche sin haber comprobado nada.
#
# El panel ya no opina. Reune los enlaces buenos para que el administrador lea
# la fuente, guarda su decision con el motivo y avisa cuando una cuarentena
# cumple el plazo. El juicio es humano y queda firmado en la auditoria.
# ---------------------------------------------------------------------------

ESTADOS_PARCHE = ("PENDIENTE", "APROBADO", "CUARENTENA", "BLOQUEADO")


def normalizar_kb(kb):
    """Deja solo los digitos. Devuelve None si no parece un numero de KB."""
    if not kb:
        return None
    limpio = re.sub(r'[^0-9]', '', str(kb))
    if not (6 <= len(limpio) <= 8):
        return None
    return limpio


def enlaces_de_kb(numero):
    """Fuentes reales, para que las lea una persona. El panel no las interpreta."""
    return {
        "microsoft": "https://support.microsoft.com/help/" + numero,
        "catalogo": "https://www.catalog.update.microsoft.com/Search.aspx?q=KB" + numero,
        "sysadmin": "https://www.reddit.com/r/sysadmin/search/?q=KB" + numero + "&restrict_sr=1&sort=new",
        "buscador": "https://www.google.com/search?q=%22KB" + numero + "%22+(issues+OR+problems+OR+bsod)&tbs=qdr:m6"
    }


def leer_estado_kb(c, numero):
    c.execute("SELECT estado, motivo, decidido_por, fecha_decision, revisar_el "
              "FROM patch_estado WHERE kb=%s", (numero,))
    fila = c.fetchone()
    if not fila:
        return {"estado": "PENDIENTE", "motivo": "", "decidido_por": "",
                "fecha_decision": None, "revisar_el": None, "revision_vencida": False}
    vencida = False
    if fila["estado"] == "CUARENTENA" and fila["revisar_el"]:
        vencida = fila["revisar_el"] <= datetime.now().date()
    return {
        "estado": fila["estado"],
        "motivo": fila["motivo"] or "",
        "decidido_por": fila["decidido_por"] or "",
        "fecha_decision": fila["fecha_decision"].strftime("%Y-%m-%d %H:%M") if fila["fecha_decision"] else None,
        "revisar_el": fila["revisar_el"].strftime("%Y-%m-%d") if fila["revisar_el"] else None,
        "revision_vencida": vencida
    }


@app.route('/api/kb/info', methods=['GET'])
def kb_info():
    es_valido, email, rol = validar_login_google(request.args.get('token'))
    if not es_valido:
        return jsonify({"status": "error", "msg": "Acceso denegado"}), 403

    numero = normalizar_kb(request.args.get('kb'))
    if not numero:
        return jsonify({"status": "error", "msg": "Numero de KB no valido."}), 400

    conn = get_db_connection()
    c = conn.cursor()
    estado = leer_estado_kb(c, numero)
    conn.close()

    return jsonify({
        "status": "ok",
        "kb": "KB" + numero,
        "enlaces": enlaces_de_kb(numero),
        "estado": estado
    })


@app.route('/api/kb/estado', methods=['POST'])
def kb_estado():
    data = request.json or {}
    es_valido, email, rol = validar_login_google(data.get('token'))
    if not es_valido or rol != "ADMIN":
        return jsonify({"status": "error", "msg": "Acceso denegado"}), 403

    numero = normalizar_kb(data.get('kb'))
    if not numero:
        return jsonify({"status": "error", "msg": "Numero de KB no valido."}), 400

    estado = (data.get('estado') or '').upper().strip()
    if estado not in ESTADOS_PARCHE:
        return jsonify({"status": "error", "msg": "Estado no valido."}), 400

    motivo = (data.get('motivo') or '').strip()[:1000]
    if estado in ("CUARENTENA", "BLOQUEADO") and not motivo:
        return jsonify({"status": "error", "msg": "Hay que escribir el motivo."}), 400

    revisar_el = None
    if estado == "CUARENTENA":
        try:
            dias = int(data.get('dias') or 7)
        except (TypeError, ValueError):
            dias = 7
        dias = max(1, min(dias, 180))
        revisar_el = (datetime.now() + timedelta(days=dias)).strftime("%Y-%m-%d")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO patch_estado (kb, estado, motivo, decidido_por, fecha_decision, revisar_el) "
        "VALUES (%s, %s, %s, %s, %s, %s) "
        "ON DUPLICATE KEY UPDATE estado=VALUES(estado), motivo=VALUES(motivo), "
        "decidido_por=VALUES(decidido_por), fecha_decision=VALUES(fecha_decision), "
        "revisar_el=VALUES(revisar_el)",
        (numero, estado, motivo, email,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"), revisar_el))
    conn.close()

    detalle = "KB" + numero
    if motivo:
        detalle = detalle + " | " + motivo
    if revisar_el:
        detalle = detalle + " | revisar el " + revisar_el
    register_audit_action("-", email, "PATCH_ESTADO", estado, detalle)

    return jsonify({"status": "ok", "kb": "KB" + numero,
                    "estado": estado, "revisar_el": revisar_el})


@app.route('/api/kb/revisiones', methods=['GET'])
def kb_revisiones():
    """Cuarentenas que han cumplido el plazo y toca volver a mirar."""
    es_valido, email, rol = validar_login_google(request.args.get('token'))
    if not es_valido:
        return jsonify({"status": "error"}), 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT kb, motivo, revisar_el FROM patch_estado "
              "WHERE estado='CUARENTENA' AND revisar_el IS NOT NULL AND revisar_el <= %s "
              "ORDER BY revisar_el ASC", (datetime.now().strftime("%Y-%m-%d"),))
    filas = c.fetchall()
    conn.close()

    return jsonify({"status": "ok", "data": [
        {"kb": "KB" + f["kb"],
         "motivo": f["motivo"] or "",
         "revisar_el": f["revisar_el"].strftime("%Y-%m-%d")}
        for f in filas
    ]})


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443, debug=False)
