import requests
import json
import subprocess
import os
from datetime import datetime
import argparse
import sys
import ctypes
import win32con
import win32gui

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "ip_checker.log")
API_KEY = "930ee27dd2d3fb1dbc551880bf0ac9456992ea3429a6b8f56889fbfb4e11ab5e1b99957c0669b060"

def hide_console():
    try:
        if sys.executable.endswith("pythonw.exe"):
            return
        
        console_window = ctypes.windll.kernel32.GetConsoleWindow()
        if console_window:
            win32gui.ShowWindow(console_window, win32con.SW_HIDE)
    except:
        pass

def escribir_log(mensaje):
    """Función robusta para escritura de logs"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {mensaje}\n"
        
        os.makedirs(SCRIPT_DIR, exist_ok=True)
        
        with open(LOG_FILE, "a", encoding='utf-8') as log_file:
            log_file.write(log_entry)
            log_file.flush()
            
    except Exception as e:
        alt_log = os.path.join(os.environ.get('TEMP', SCRIPT_DIR), 'ip_checker_fallback.log')
        try:
            with open(alt_log, "a", encoding='utf-8') as f:
                f.write(f"[{timestamp}] Error en log principal: {str(e)}\n")
                f.write(f"[{timestamp}] Mensaje original: {mensaje}\n")
        except:
            pass

def checarIP(ip):
    """Consulta la API con manejo mejorado de errores"""
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': API_KEY}

        response = requests.request('GET', url, headers=headers, params=querystring)
        response.raise_for_status()

        data = json.loads(response.text).get('data', {})
        
        score = data.get('abuseConfidenceScore', 0)
        reports = data.get('totalReports', 0)
        isp = data.get('isp', 'Desconocido')
        country = data.get('countryName', 'Desconocido')
        
        if score == 0 and reports == 0:
            status = "CLEAN"
            message = f"IP {ip} (ISP: {isp}, País: {country}) - No tiene reportes"
        elif score < 50:
            status = "WARNING"
            message = f"IP {ip} (ISP: {isp}, País: {country}) - {reports} reportes (Score: {score}%)"
        else:
            status = "DANGER"
            message = f"IP {ip} (ISP: {isp}, País: {country}) - ALTO RIESGO! {reports} reportes (Score: {score}%)"
        
        log_msg = f"{message} [{status}]"
        escribir_log(log_msg)
        return log_msg

    except Exception as e:
        error_msg = f"Error verificando {ip}: {str(e)}"
        escribir_log(error_msg)
        return error_msg

def ejecutar_powershell():
    """Ejecuta el script PowerShell de forma confiable"""
    ps_script = os.path.join(SCRIPT_DIR, "IPsActivas.ps1")
    
    if not os.path.exists(ps_script):
        escribir_log(f"Error: No se encontró {ps_script}")
        return None

    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        result = subprocess.run(
            ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", ps_script],
            startupinfo=startupinfo,
            capture_output=True,
            text=True,
            check=True,
            timeout=60
        )
        
        ips = [ip.strip() for ip in result.stdout.splitlines() if ip.strip()]
        escribir_log(f"IPs detectadas: {', '.join(ips) if ips else 'Ninguna'}")
        return ips

    except subprocess.TimeoutExpired:
        escribir_log("Error: Timeout al ejecutar PowerShell")
        return None
    except Exception as e:
        escribir_log(f"Error ejecutando PowerShell: {str(e)}")
        return None

def main():
    hide_console()
    escribir_log("=== Inicio de ejecución ===")
    
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-i', '--ips', nargs='+', help='IPs a verificar')
        args = parser.parse_args()

        ips = args.ips if args.ips else ejecutar_powershell()
        if not ips:
            escribir_log("No hay IPs para verificar")
            return

        escribir_log(f"Verificando {len(ips)} IPs...")
        for ip in ips[:3]:
            resultado = checarIP(ip)
            escribir_log(resultado)

    except Exception as e:
        escribir_log(f"Error crítico: {str(e)}")
    finally:
        escribir_log("=== Fin de ejecución ===\n")

if __name__ == "__main__":
    main()
