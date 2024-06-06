# CyberSpectra
 "CyberSpectra" es una herramienta avanzada de análisis de seguridad cibernética que se centra en la detección de anomalías y la protección de redes y sistemas.
# CyberSpectra

CyberSpectra es una herramienta de análisis de seguridad de redes Wi-Fi y tráfico de red escrita en Perl. Proporciona funciones para analizar redes Wi-Fi, evaluar la fortaleza de las contraseñas, capturar y analizar paquetes de red, y detectar posibles anomalías en el tráfico IP.

## Características principales

- Análisis de redes Wi-Fi: Escanea y muestra información detallada sobre las redes Wi-Fi disponibles, incluyendo SSID y cifrado.
- Evaluación de contraseñas: Verifica la fortaleza de las contraseñas utilizadas en redes Wi-Fi y proporciona sugerencias para mejorarlas.
- Captura y análisis de tráfico de red: Captura y analiza paquetes de red para detectar tráfico SSH y posibles anomalías en el tráfico IP.
- Interfaz de usuario amigable: Proporciona una interfaz gráfica de usuario (GUI) intuitiva para visualizar los resultados del análisis.

## Requisitos previos

Antes de ejecutar CyberSpectra, asegúrate de tener instaladas las siguientes dependencias:

- Net::Wireless::80211
- Net::Wifi
- Net::Pcap
- NetPacket::Ethernet
- NetPacket::IP
- NetPacket::TCP
- Crypt::PasswdMD5
- Password::Policy
- Term::ANSIColor
- Parallel::ForkManager
- Tk
- Tk::Table

Puedes instalar estas dependencias utilizando el gestor de paquetes de Perl, como cpanm o cpan.

#script de instalacion con cpanm en bash
'
#!/bin/bash

# Ensure cpanm is installed
if ! command -v cpanm &> /dev/null
then
    echo "cpanm could not be found, installing..."
    cpan App::cpanminus
fi

# Install required Perl modules
cpanm Net::Wireless::80211
cpanm Net::Wifi
cpanm Net::Pcap
cpanm NetPacket::Ethernet
cpanm NetPacket::IP
cpanm NetPacket::TCP
cpanm Crypt::PasswdMD5
cpanm Password::Policy
cpanm Tk
cpanm Tk::Table
cpanm Parallel::ForkManager

echo "All modules installed successfully."
'

## Uso

1. Clona este repositorio en tu máquina local.
2. Instala las dependencias mencionadas en la sección "Requisitos previos".
3. Ejecuta el archivo `cyberspectra.pl` utilizando Perl.

4. Se abrirá la interfaz gráfica de usuario (GUI) de CyberSpectra.
5. Utiliza las opciones y funciones disponibles en la interfaz para realizar análisis de seguridad de redes Wi-Fi y tráfico de red.

## Contribución

¡Las contribuciones son bienvenidas! Si deseas mejorar CyberSpectra, envía tus propuestas a través de pull requests. Antes de realizar cambios importantes, asegúrate de discutirlos en la sección de problemas (issues) para obtener comentarios adicionales.

## Licencia

CyberSpectra es creado por NahuelEspinoza y se distribuye bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para obtener más información.

