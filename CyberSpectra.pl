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
use Parallel::ForkManager;

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

    my $policy = Password::Policy->new(length => {min => 8});

    # Realizar análisis de seguridad de la contraseña
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

    my $desencriptada = Crypt::PasswdMD5::apache_md5_crypt('', $contraseña_encriptada);

    return $desencriptada;
}

# Función para mostrar la contraseña desencriptada
sub mostrar_contraseña_desencriptada {
    my ($contraseña_encriptada) = @_;

    my $contraseña_desencriptada = desencriptar_contraseña($contraseña_encriptada);

    print "Contraseña desencriptada: $contraseña_desencriptada\n";
}

# Función para capturar y analizar el tráfico de red en una red Wi-Fi específica
sub analizar_trafico_red {
    my $dev = Net::Pcap::lookupdev(\my $err);
    die "No se puede encontrar el dispositivo de red: $err" if $err;
    my $pcap = Net::Pcap::open_live($dev, 1500, 0, 1000, \$err);
    die "No se puede abrir el dispositivo de captura: $err" if $err;

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

        if ($src_port == 22 || $dst_port == 22) {
            print "Se detectó tráfico en el puerto SSH (22).\n";
            ejecutar_acciones_ssh($ip_pkt);
        }
    }
}

# Función para ejecutar acciones adicionales en tráfico SSH detectado
sub ejecutar_acciones_ssh {
    my ($ip_pkt) = @_;

    my $src_ip = $ip_pkt->{src_ip};
    my $dst_ip = $ip_pkt->{dest_ip};
    my $timestamp = scalar localtime;

    print "Intento de acceso SSH fallido desde $src_ip hacia $dst_ip a las $timestamp.\n";
}

# Función para analizar anomalías en paquetes IP
sub analizar_anomalías {
    my ($ip_pkt) = @_;
    # Implementar algoritmos para detectar anomalías en el tráfico IP
}

# Función para auditar la fortaleza de las contraseñas utilizadas en las redes Wi-Fi
sub auditar_contraseñas {
    my @redes = Net::Wifi::scan();

    foreach my $red (@redes) {
        print "SSID: " . $red->{ssid} . "\n";

        if ($red->{encryption} =~ /WPA/i) {
            evaluar_contraseña($red->{password});
            mostrar_contraseña_desencriptada($red->{password});
        }

        print "---\n";
    }
}

# Función principal del programa
sub main {
    create_gui();

    my $pm = Parallel::ForkManager->new(2);

    $pm->start and next;
    eval { analizar_redes_wifi(); };
    if ($@) { print "Error en el análisis de redes Wi-Fi: $@\n"; }
    $pm->finish;

    $pm->start and next;
    eval { analizar_trafico_red(); };
    if ($@) { print "Error en el análisis de tráfico de red: $@\n"; }
    $pm->finish;

    $pm->wait_all_children;

    $main_window->MainLoop;
}

# Función para crear la interfaz de usuario
sub create_gui {
    $main_window = MainWindow->new;
    $main_window->title("Análisis de Seguridad de Redes");

    $table = $main_window->Scrolled('Table', -scrollbars => 'se')->pack;
    $table->configure(-rows => 10, -cols => 2);

    $table->set(0, 0, "SSID");
    $table->set(0, 1, "Cifrado");

    $table->tagConfigure('header', -foreground => 'white', -background => 'black');
    $table->tagConfigure('data', -foreground => 'black');

    $table->tagRow('header', 0);

    sub update_table {
        my ($ssid, $cifrado) = @_;

        $table_row++;
        $table->set($table_row, 0, $ssid);
        $table->set($table_row, 1, $cifrado);

        $table->tagRow('data', $table_row);
        $table->configure(-scrollregion => [$table->bbox('all')]);
    }
}

main();
