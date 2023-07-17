use strict;
use warnings;
use Net::Wireless::80211;
use Net::Wifi;
use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP;
use NetPacket::TCP;
use Crypt::PasswdMD5;
use Password::Policy;
use Tk;
use Tk::Table;

# Configuración
my $interface = "eth0";
my @analysis_algorithms = ("SSH", "Anomaly");  # Algoritmos de análisis a aplicar
my $anomaly_threshold = 10;  # Umbral para detección de anomalías

# Variables globales
my $main_window;
my $table;
my $table_row = 0;

# Función para realizar el análisis de seguridad de redes Wi-Fi
sub analizar_redes_wifi {
    my @redes = Net::Wifi::scan();

    foreach my $red (@redes) {
        print "SSID: " . $red->{ssid} . "\n";
        print "Cifrado: " . $red->{encryption} . "\n";

        if ($red->{encryption} =~ /WPA/i) {
            # Verificar la fortaleza de la contraseña
            evaluar_contraseña($red->{password});
        }

        print "---\n";
    }
}

# Función para evaluar la fortaleza de la contraseña
sub evaluar_contraseña {
    my ($contraseña) = @_;

    my $policy = Password::Policy->new;

    # Realizar análisis de seguridad de la contraseña
    my $length = length $contraseña;
    my $is_secure = $policy->check($contraseña);

    if ($is_secure) {
        print "La contraseña cumple con los estándares de seguridad.\n";
    } else {
        print "La contraseña no cumple con los estándares de seguridad.\n";
        # Realizar otras acciones, como sugerir medidas para mejorar la contraseña
        sugerir_medidas_contraseña($contraseña);
    }
}

# Función para sugerir medidas para mejorar la contraseña
sub sugerir_medidas_contraseña {
    my ($contraseña) = @_;

    # Realizar análisis de la contraseña y proporcionar sugerencias para mejorarla
    # Aquí puedes implementar algoritmos para sugerir medidas como longitud mínima,
    # caracteres especiales, combinación de mayúsculas y minúsculas, etc.
    # Por ejemplo:
    my $sugerencias = "";
    $sugerencias .= "Aumentar la longitud de la contraseña.\n" if length($contraseña) < 10;
    $sugerencias .= "Incluir caracteres especiales en la contraseña.\n" if $contraseña !~ /[!@#$%^&*()]/;
    $sugerencias .= "Incluir letras mayúsculas y minúsculas en la contraseña.\n" if $contraseña !~ /[A-Z]/ || $contraseña !~ /[a-z]/;

    if ($sugerencias ne "") {
        print "Sugerencias para mejorar la contraseña:\n";
        print $sugerencias;
    }
}

# Función para desencriptar una contraseña
sub desencriptar_contraseña {
    my ($contraseña_encriptada) = @_;

    # Desencriptar la contraseña utilizando el algoritmo correspondiente
    # Asume que se está utilizando Crypt::PasswdMD5 para encriptar las contraseñas
    my $desencriptada = Crypt::PasswdMD5::apache_md5_crypt('', $contraseña_encriptada);

    return $desencriptada;
}

# Función para mostrar la contraseña desencriptada
sub mostrar_contraseña_desencriptada {
    my ($contraseña_encriptada) = @_;

    # Desencriptar la contraseña
    my $contraseña_desencriptada = desencriptar_contraseña($contraseña_encriptada);

    # Mostrar la contraseña desencriptada
    print "Contraseña desencriptada: $contraseña_desencriptada\n";
}

# Función para capturar y analizar el tráfico de red en una red Wi-Fi específica
sub analizar_trafico_red {
    my $dev = Net::Pcap::lookupdev(\my $err);
    my $pcap = Net::Pcap::open_live($dev, 1500, 0, 1000, \$err);

    Net::Pcap::loop($pcap, -1, \&capturar_paquete, "");

    Net::Pcap::close($pcap);
}

# Función para capturar y analizar paquetes de red
sub capturar_paquete {
    my ($user_data, $header, $packet) = @_;

    my $eth_pkt = NetPacket::Ethernet->decode($packet);

    if ($eth_pkt->{type} == 0x0800) {
        my $ip_pkt = NetPacket::IP->decode($eth_pkt->{data});
        # Realizar análisis adicional de los paquetes IP capturados
        analizar_paquete_ip($ip_pkt);
    }
}

# Función para analizar paquetes IP
sub analizar_paquete_ip {
    my ($ip_pkt) = @_;

    # Realizar análisis de tráfico y detección de patrones inusuales
    # Implementar algoritmos de análisis, como estadísticas de flujo,
    # análisis de puertos, reconocimiento de firmas de ataques, etc.
    foreach my $algorithm (@analysis_algorithms) {
        if ($algorithm eq "SSH") {
            analizar_tráfico_ssh($ip_pkt);
        } elsif ($algorithm eq "Anomaly") {
            analizar_anomalías($ip_pkt);
        }
    }
}

# Función para analizar tráfico SSH
sub analizar_tráfico_ssh {
    my ($ip_pkt) = @_;

    if ($ip_pkt->{proto} == 6) {
        my $tcp_pkt = NetPacket::TCP->decode($ip_pkt->{data});
        my $src_port = $tcp_pkt->{src_port};
        my $dst_port = $tcp_pkt->{dest_port};

        # Realizar acciones en función de los puertos detectados
        if ($src_port == 22 || $dst_port == 22) {
            print "Se detectó tráfico en el puerto SSH (22).\n";
            # Ejecutar acciones adicionales, como alertas o bloqueo de tráfico sospechoso
            ejecutar_acciones_ssh($ip_pkt);
        }
    }
}

# Función para ejecutar acciones adicionales en tráfico SSH detectado
sub ejecutar_acciones_ssh {
    my ($ip_pkt) = @_;

    # Aquí puedes implementar acciones adicionales en caso de detectar tráfico SSH
    # Por ejemplo, registrar intentos de acceso, bloquear direcciones IP sospechosas, etc.
    # Puedes acceder a la información del paquete IP para obtener detalles adicionales

    # Ejemplo: Registrar intentos de acceso SSH fallidos
    my $src_ip = $ip_pkt->{src_ip};
    my $dst_ip = $ip_pkt->{dest_ip};
    my $timestamp = scalar localtime;

    print "Intento de acceso SSH fallido desde $src_ip hacia $dst_ip a las $timestamp.\n";
}

# Función para analizar anomalías en paquetes IP
sub analizar_anomalías {
    my ($ip_pkt) = @_;

    # Implementar algoritmos para detectar anomalías en el tráfico IP
    # Por ejemplo, puedes analizar el tamaño de los paquetes, el tiempo entre paquetes, etc.
    # Realizar acciones en caso de detectar anomalías
}

# Función para auditar la fortaleza de las contraseñas utilizadas en las redes Wi-Fi
sub auditar_contraseñas {
    my @redes = Net::Wifi::scan();

    foreach my $red (@redes) {
        print "SSID: " . $red->{ssid} . "\n";

        if ($red->{encryption} =~ /WPA/i) {
            # Verificar la fortaleza de la contraseña
            evaluar_contraseña($red->{password});
            # Desencriptar la contraseña y mostrarla
            mostrar_contraseña_desencriptada($red->{password});
        }

        print "---\n";
    }
}

# Función principal del programa
sub main {
    # Crear la interfaz de usuario
    create_gui();

    # Crear un administrador de procesos en paralelo
    my $pm = Parallel::ForkManager->new(2);  # Ejecutar hasta 2 procesos en paralelo

    # Tarea 1: Análisis de redes Wi-Fi
    $pm->start and next;
    eval {
        analizar_redes_wifi();
    };
    if ($@) {
        print "Error en el análisis de redes Wi-Fi: $@\n";
    }
    $pm->finish;

    # Tarea 2: Análisis de tráfico de red
    $pm->start and next;
    eval {
        analizar_trafico_red();
    };
    if ($@) {
        print "Error en el análisis de tráfico de red: $@\n";
    }
    $pm->finish;

    # Esperar a que finalicen todas las tareas en paralelo
    $pm->wait_all_children;

    # Mostrar la interfaz de usuario
    $main_window->MainLoop;
}

# Función para crear la interfaz de usuario
sub create_gui {
    $main_window = MainWindow->new;
    $main_window->title("Análisis de Seguridad de Redes");

    # Crear una tabla para mostrar los resultados
    $table = $main_window->Scrolled('Table', -scrollbars => 'se')->pack;
    $table->configure(-rows => 10, -cols => 2);

    # Encabezados de la tabla
    $table->set(0, 0, "SSID");
    $table->set(0, 1, "Cifrado");

    # Configuración de la tabla
    $table->tagConfigure('header', -foreground => 'white', -background => 'black');
    $table->tagConfigure('data', -foreground => 'black');

    $table->tagRow('header', 0);

    # Actualizar la tabla con los resultados
    sub update_table {
        my ($ssid, $cifrado) = @_;

        $table_row++;
        $table->set($table_row, 0, $ssid);
        $table->set($table_row, 1, $cifrado);

        $table->tagRow('data', $table_row);
        $table->configure(-scrollregion => [$table->bbox('all')]);
    }

    # Asociar la función de actualización a la salida estándar
    *STDOUT = *STDERR = *update_table;
}

# Llamada a la función principal del programa
main();
