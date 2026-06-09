import socket
import ipaddress
import sys

PORTAS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP Alternativo"
}


def gerar_ips(ip_inicial, ip_final):
    inicio = ipaddress.IPv4Address(ip_inicial)
    fim = ipaddress.IPv4Address(ip_final)

    return [
        str(ipaddress.IPv4Address(ip))
        for ip in range(int(inicio), int(fim) + 1)
    ]


def testar_porta(ip, porta, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        resultado = sock.connect_ex((ip, porta))
        sock.close()

        return resultado == 0

    except:
        return False


def host_ativo(ip):
    for porta in PORTAS:
        if testar_porta(ip, porta):
            return True

    return False


def obter_portas_abertas(ip):
    abertas = []

    for porta in PORTAS:
        if testar_porta(ip, porta):
            abertas.append(porta)

    return abertas


def main():

    if len(sys.argv) != 3:
        print("Uso:")
        print("python NetAudit.py IP_INICIAL IP_FINAL")
        return

    ip_inicial = sys.argv[1]
    ip_final = sys.argv[2]

    ips = gerar_ips(ip_inicial, ip_final)

    print("=" * 40)
    print("RELATÓRIO DE AUDITORIA")
    print("=" * 40)

    for ip in ips:

        print(f"\nHost: {ip}")

        if not host_ativo(ip):
            print("Status: Inativo ou sem resposta")
            continue

        print("Status: Ativo")

        abertas = obter_portas_abertas(ip)

        print("Portas abertas:")

        for porta in abertas:
            print(f"  {porta}/tcp - {PORTAS[porta]}")


if __name__ == "__main__":
    main()