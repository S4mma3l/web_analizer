# Web Analyzer

**Web Analyzer** es una herramienta de análisis de URLs que permite obtener información detallada sobre un sitio web, incluyendo la dirección IP, información del dominio, puertos abiertos, certificados SSL, reputación en línea y más. Esta herramienta es útil para expertos en ciberseguridad, investigadores y cualquier persona interesada en evaluar la seguridad y reputación de un sitio web.

## Características

- **Análisis de Dominio**: Obtiene información sobre la dirección IP y los detalles del registro del dominio.
- **Escaneo de Puertos**: Utiliza Nmap para escanear puertos abiertos en el servidor del sitio web.
- **Verificación de Certificados SSL**: Comprueba la validez del certificado SSL y su fecha de expiración.
- **Reputación en VirusTotal**: Verifica la reputación del URL en VirusTotal para identificar posibles amenazas.
- **Extracción de Correos Electrónicos**: Extrae correos electrónicos de la página web para facilitar la investigación.
- **Integración con Shodan**: Busca información adicional sobre el sitio utilizando la API de Shodan.

## Requisitos

- Python 3.x
- Paquetes de Python requeridos:
  - `requests`
  - `beautifulsoup4`
  - `python-nmap`
  - `python-whois`
  - `shodan`
  - `ssl`

## Instalación

1. Clona este repositorio en tu máquina local:

   ```bash
   git clone 
   cd web-analyzer

   pip install -r requirements.txt
2. Crear un archivo key.py donde ingresaras tus:
    SHODAN_KEY = 'tu_clave_de_shodan'
    VIRUS_TOTAL = 'tu_clave_de_virustotal'

