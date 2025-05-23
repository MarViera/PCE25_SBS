"""Script 3er parcial."""
import requests
import json
import subprocess
import os
from datetime import datetime
import argparse
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "ip_checker.log")
API_KEY = ("930ee27dd2d3fb1dbc551880bf0ac9456992ea3"
           "429a6b8f56889fbfb4e11ab5e1b99957c0669b060")


def escribir_log(mensaje):
    """Escribe un mensaje en el archivo de log con timestamp."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding='utf-8') as log_file:
            log_file.write(f"[{timestamp}] {mensaje}\n")
    except (IOError, PermissionError) as e:
        print(f"Error al escribir en el log: {str(e)}", file=sys.stderr)


def checarip(ip):
    """Consulta la API de Abuse IP DB con manejo básico de errores."""
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': API_KEY
        }

        response = requests.request(
            method='GET',
            url=url,
            headers=headers,
            params=querystring
        )
        response.raise_for_status()

        decodedresponse = json.loads(response.text)
        if 'data' not in decodedresponse:
            raise ValueError("Respuesta de API no contiene datos esperados")

        data = decodedresponse['data']
        abuseconfidencescore = data.get('abuseconfidencescore', 0)
        totalreports = data.get('totalreports', 0)
        isp = data.get('isp', 'Desconocido')
        country = data.get('countryName', 'Desconocido')
        if abuseconfidencescore == 0 and totalreports == 0:
            resultado = (f"IP {ip} (ISP: {isp}, País: {country}) - "
                f"No tiene reportes en AbuseIPDB [CLEAN]")
        elif abuseconfidencescore < 50:
            resultado = (f"IP {ip} (ISP: {isp}, País: {country}) - "
                f"Tiene {totalreports} reportes "
                f"(Confianza de abuso: {abuseconfidencescore}%) [WARNING]")
        else:
            resultado = (f"IP {ip} (ISP: {isp}, País: {country}) - "
                f"ALTO RIESGO! {totalreports} reportes " \
                f"(Confianza de abuso: {abuseconfidencescore}%) [DANGER]")
        escribir_log(f"Resultado verificación IP: {resultado}")
        return resultado

    except requests.exceptions.RequestException as e:
        error_msg = f"Error de conexión con la API para IP {ip}: {str(e)}"
        escribir_log(error_msg)
        return f"Error: No se pudo verificar la IP {ip} (Error de conexión)"
    except (json.JSONDecodeError, ValueError) as e:
        error_msg = f"Error procesando respuesta para IP {ip}: {str(e)}"
        escribir_log(error_msg)
        return f"Error: Respuesta inválida de la API para IP {ip}"
    except Exception as e:
        error_msg = f"Error inesperado al verificar IP {ip}: {str(e)}"
        escribir_log(error_msg)
        return f"Error inesperado al verificar IP {ip}"


def obtener_ips_activas():
    """Obtiene las IPs activas con manejo básico de errores."""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        ps_script_path = os.path.join(script_dir, "IPsActivas.ps1")
        if not os.path.exists(ps_script_path):
            raise FileNotFoundError(
                f"No se encontró el archivo {ps_script_path}"
            )
        command = [
            "powershell.exe",
            "-ExecutionPolicy", "Bypass",
            "-File", ps_script_path
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        ips = [ip.strip() for ip in result.stdout.splitlines() if ip.strip()]
        escribir_log(f"IPs activas encontradas: {', '.join(ips)}")
        return ips
    except FileNotFoundError as e:
        error_msg = f"Error crítico: {str(e)}"
        print(error_msg, file=sys.stderr)
        escribir_log(error_msg)
        return None
    except subprocess.CalledProcessError as e:
        error_msg = (
            f"Error al ejecutar PowerShell (código {e.returncode}): "
            f"{e.stderr.strip()}"
        )
        print(error_msg, file=sys.stderr)
        escribir_log(error_msg)
        return None
    except Exception as e:
        error_msg = f"Error inesperado al obtener IPs activas: {str(e)}"
        print(error_msg, file=sys.stderr)
        escribir_log(error_msg)
        return None


def main():
    """Funcion main."""
    try:
        parser = argparse.ArgumentParser(
            description='Verificación de IPs en AbuseIPDB'
        )
        parser.add_argument(
            '-i',
            '--ips',
            nargs='+',
            help='Lista de IPs a verificar (separadas por espacios)'
        )
        args = parser.parse_args()

        escribir_log("Inicio de ejecución del script")
        print("Script de verificación de IPs en AbuseIPDB")
        if args.ips:
            print("\nVerificando IPs proporcionadas:")
            ips = args.ips
            for i, ip in enumerate(ips, 1):
                print(f"{i}. {ip}")
        else:
            print("\nObteniendo IPs activas...")
            ips = obtener_ips_activas()
            if not ips:
                print(
                "No se pudieron obtener las IPs activas. "
                "Verifique el log para más detalles."
                )
                return
            print("\nIPs conectadas al equipo:")
            for i, ip in enumerate(ips, 1):
                print(f"{i}. {ip}")
        print(f"\nTotal: {len(ips)} IPs únicas")
        ips_a_verificar = ips[:3]
        print("\nAnalizando IPs sospechosas (limitado a 3 IPs):")
        for ip in ips_a_verificar:
            resultado = checarip(ip)
            print(resultado)
    except KeyboardInterrupt:
        print("\nEjecución interrumpida por el usuario")
        escribir_log("Ejecución interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        error_msg = f"Error crítico en la ejecución principal: {str(e)}"
        print(error_msg, file=sys.stderr)
        escribir_log(error_msg)
        sys.exit(1)
    finally:
        escribir_log("Fin de ejecución del script\n")


if __name__ == "__main__":
    main()
