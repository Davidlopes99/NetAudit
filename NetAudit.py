import socket
import ipaddress
import argparse

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

PORTAS_INSEGURAS = {21, 23, 110}
PORTAS_MEDIAS = {22, 3306, 5432}
PORTAS_WEB = {80, 443}


def gerar_ips(ip_inicial, ip_final):
    inicio = ipaddress.IPv4Address(ip_inicial)
    fim = ipaddress.IPv4Address(ip_final)

    if inicio > fim:
        raise ValueError("O IP inicial não pode ser maior que o IP final.")

    return [str(ipaddress.IPv4Address(ip)) for ip in range(int(inicio), int(fim) + 1)]


def testar_porta(ip, porta, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        resultado = sock.connect_ex((ip, porta))
        sock.close()

        if resultado == 0:
            return "Aberta"
        elif resultado in [61, 111, 10061]:
            return "Fechada"
        else:
            return "Filtrada ou sem resposta"

    except:
        return "Filtrada ou sem resposta"


def varrer_host(ip, portas, timeout):
    return {porta: testar_porta(ip, porta, timeout) for porta in portas}


def host_ativo(resultado_portas):
    return any(estado in ["Aberta", "Fechada"] for estado in resultado_portas.values())


def obter_servico(porta):
    return PORTAS.get(porta, "Serviço desconhecido")


def classificar_risco(portas_abertas):
    abertas = set(portas_abertas)

    if abertas & PORTAS_INSEGURAS:
        return "Alto"

    if abertas & PORTAS_MEDIAS:
        return "Médio"

    if abertas and abertas <= PORTAS_WEB:
        return "Baixo"

    return "Indefinido"


def motivos_risco(portas_abertas):
    motivos = {
        21: "FTP pode transmitir dados e credenciais sem criptografia.",
        23: "Telnet é um protocolo sem criptografia e não deve ser exposto.",
        110: "POP3 pode expor credenciais caso não utilize criptografia.",
        22: "SSH é um serviço administrativo e deve estar bem protegido.",
        3306: "MySQL exposto pode representar risco ao banco de dados.",
        5432: "PostgreSQL exposto pode representar risco ao banco de dados."
    }

    return [motivos[p] for p in portas_abertas if p in motivos]


def converter_portas(texto):
    portas = [int(p.strip()) for p in texto.split(",")]

    for porta in portas:
        if porta < 1 or porta > 65535:
            raise ValueError("As portas devem estar entre 1 e 65535.")

    return portas


def gerar_relatorio(ips, portas, timeout):
    linhas = []
    ativos = sem_resposta = total_abertas = 0
    riscos = {"Alto": 0, "Médio": 0, "Baixo": 0, "Indefinido": 0}

    linhas.append("=" * 40)
    linhas.append("RELATÓRIO DE AUDITORIA DE REDE")
    linhas.append("=" * 40)

    for ip in ips:
        linhas.append(f"\nHost: {ip}")

        resultado = varrer_host(ip, portas, timeout)

        if not host_ativo(resultado):
            sem_resposta += 1
            linhas.append("Status: Inativo ou sem resposta")
            linhas.append("-" * 40)
            continue

        ativos += 1
        abertas = [porta for porta, estado in resultado.items() if estado == "Aberta"]
        total_abertas += len(abertas)

        linhas.append("Status: Ativo")

        if abertas:
            linhas.append("\nPortas abertas:")
            for porta in abertas:
                linhas.append(f"  {porta}/tcp    {obter_servico(porta)}")
        else:
            linhas.append("\nNenhuma porta aberta encontrada.")

        risco = classificar_risco(abertas)
        riscos[risco] += 1

        linhas.append(f"\nRisco: {risco}")

        motivos = motivos_risco(abertas)
        if motivos:
            linhas.append("Motivo:")
            for motivo in motivos:
                linhas.append(f"  - {motivo}")

        linhas.append("-" * 40)

    linhas.append("\nResumo:")
    linhas.append(f"Hosts analisados: {len(ips)}")
    linhas.append(f"Hosts ativos: {ativos}")
    linhas.append(f"Hosts sem resposta: {sem_resposta}")
    linhas.append(f"Total de portas abertas: {total_abertas}")
    linhas.append(f"Hosts com risco alto: {riscos['Alto']}")
    linhas.append(f"Hosts com risco médio: {riscos['Médio']}")
    linhas.append(f"Hosts com risco baixo: {riscos['Baixo']}")
    linhas.append(f"Hosts com risco indefinido: {riscos['Indefinido']}")

    return "\n".join(linhas)


def main():
    parser = argparse.ArgumentParser(description="NetAudit - Auditoria básica de serviços em rede")

    parser.add_argument("ip_inicial")
    parser.add_argument("ip_final")
    parser.add_argument("-p", "--portas", help="Portas separadas por vírgula. Ex: 22,80,443")
    parser.add_argument("-o", "--output", help="Arquivo para salvar o relatório")
    parser.add_argument("--timeout", type=float, default=1, help="Timeout em segundos")

    args = parser.parse_args()

    try:
        ips = gerar_ips(args.ip_inicial, args.ip_final)
        portas = converter_portas(args.portas) if args.portas else list(PORTAS.keys())

        relatorio = gerar_relatorio(ips, portas, args.timeout)
        print(relatorio)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as arquivo:
                arquivo.write(relatorio)

            print(f"\nRelatório salvo em: {args.output}")

    except ValueError as erro:
        print(f"Erro: {erro}")

    except KeyboardInterrupt:
        print("\nExecução interrompida pelo usuário.")


if __name__ == "__main__":
    main()