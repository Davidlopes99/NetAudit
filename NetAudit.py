import socket
import ipaddress
import argparse
import errno
import time

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
    8080: "HTTP Alternativo",
}

PORTAS_INSEGURAS = {21, 23, 110}
PORTAS_MEDIAS = {22, 3306, 5432}
PORTAS_WEB = {80, 443, 8080}

CODIGOS_PORTA_FECHADA = {
    errno.ECONNREFUSED,
    61,
    111,
    10061,
}


def gerar_ips(ip_inicial, ip_final):
    inicio = ipaddress.IPv4Address(ip_inicial)
    fim = ipaddress.IPv4Address(ip_final)

    if inicio > fim:
        raise ValueError(
            "O IP inicial não pode ser maior que o IP final."
        )

    return [
        str(ipaddress.IPv4Address(ip))
        for ip in range(int(inicio), int(fim) + 1)
    ]


def testar_porta(ip, porta, timeout):
    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:
            sock.settimeout(timeout)
            resultado = sock.connect_ex((ip, porta))

        if resultado == 0:
            return "Aberta"

        if resultado in CODIGOS_PORTA_FECHADA:
            return "Fechada"

        return "Filtrada ou sem resposta"

    except (socket.timeout, OSError):
        return "Filtrada ou sem resposta"


def varrer_host(ip, portas, timeout):
    return {
        porta: testar_porta(ip, porta, timeout)
        for porta in portas
    }


def host_ativo(resultado_portas):
    return any(
        estado in {"Aberta", "Fechada"}
        for estado in resultado_portas.values()
    )


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
        21: (
            "FTP pode transmitir dados e credenciais "
            "sem criptografia."
        ),
        23: (
            "Telnet é um protocolo sem criptografia "
            "e não deve ser exposto."
        ),
        110: (
            "POP3 pode expor credenciais caso não utilize "
            "criptografia."
        ),
        22: (
            "SSH é um serviço administrativo e deve estar "
            "bem protegido."
        ),
        3306: (
            "MySQL exposto pode representar risco ao "
            "banco de dados."
        ),
        5432: (
            "PostgreSQL exposto pode representar risco ao "
            "banco de dados."
        ),
    }

    return [
        motivos[porta]
        for porta in portas_abertas
        if porta in motivos
    ]


def converter_portas(texto):
    try:
        portas = [
            int(porta.strip())
            for porta in texto.split(",")
            if porta.strip()
        ]

    except ValueError as erro:
        raise ValueError(
            "As portas devem ser números separados por vírgula."
        ) from erro

    if not portas:
        raise ValueError(
            "É necessário informar pelo menos uma porta."
        )

    for porta in portas:
        if porta < 1 or porta > 65535:
            raise ValueError(
                "As portas devem estar entre 1 e 65535."
            )

    # Remove portas repetidas, mantendo a ordem informada.
    return list(dict.fromkeys(portas))


def formatar_tempo(segundos):
    if segundos < 60:
        return f"{segundos:.2f} segundos"

    minutos = int(segundos // 60)
    segundos_restantes = segundos % 60

    return (
        f"{minutos} minuto(s) e "
        f"{segundos_restantes:.2f} segundo(s)"
    )


def gerar_relatorio(ips, portas, timeout):
    linhas = []
    ativos = 0
    sem_resposta = 0
    total_abertas = 0

    riscos = {
        "Alto": 0,
        "Médio": 0,
        "Baixo": 0,
        "Indefinido": 0,
    }

    total_ips = len(ips)
    inicio_execucao = time.perf_counter()

    linhas.append("=" * 48)
    linhas.append("RELATÓRIO DE AUDITORIA DE REDE")
    linhas.append("=" * 48)
    linhas.append(f"Faixa analisada: {ips[0]} até {ips[-1]}")
    linhas.append(f"Quantidade de hosts: {total_ips}")
    linhas.append(f"Portas testadas: {', '.join(map(str, portas))}")
    linhas.append(f"Timeout utilizado: {timeout} segundo(s)")

    print()
    print("=" * 48)
    print("NETAUDIT - AUDITORIA BÁSICA DE REDE")
    print("=" * 48)
    print(f"Faixa: {ips[0]} até {ips[-1]}")
    print(f"Hosts a analisar: {total_ips}")
    print(f"Portas por host: {len(portas)}")
    print(f"Timeout: {timeout} segundo(s)")

    estimativa_maxima = total_ips * len(portas) * timeout

    print(
        "Tempo máximo estimado: "
        f"{formatar_tempo(estimativa_maxima)}"
    )
    print()
    print("Iniciando auditoria...")
    print()

    for indice, ip in enumerate(ips, start=1):
        print(
            f"[{indice}/{total_ips}] Analisando {ip}...",
            end=" ",
            flush=True,
        )

        linhas.append("")
        linhas.append(f"Host: {ip}")

        resultado = varrer_host(ip, portas, timeout)

        if not host_ativo(resultado):
            sem_resposta += 1

            linhas.append("Status: Inativo ou sem resposta")
            linhas.append("-" * 48)

            print("Inativo ou sem resposta")
            continue

        ativos += 1

        abertas = [
            porta
            for porta, estado in resultado.items()
            if estado == "Aberta"
        ]

        total_abertas += len(abertas)

        linhas.append("Status: Ativo")

        if abertas:
            quantidade = len(abertas)

            print(
                f"Ativo - {quantidade} porta(s) aberta(s)"
            )

            linhas.append("")
            linhas.append("Portas abertas:")

            for porta in abertas:
                linhas.append(
                    f"  {porta}/tcp    {obter_servico(porta)}"
                )

        else:
            print("Ativo - nenhuma porta aberta")

            linhas.append("")
            linhas.append(
                "Nenhuma porta aberta encontrada."
            )

        risco = classificar_risco(abertas)
        riscos[risco] += 1

        linhas.append("")
        linhas.append(f"Risco: {risco}")

        motivos = motivos_risco(abertas)

        if motivos:
            linhas.append("Motivo:")

            for motivo in motivos:
                linhas.append(f"  - {motivo}")

        linhas.append("-" * 48)

    tempo_total = time.perf_counter() - inicio_execucao

    linhas.append("")
    linhas.append("=" * 48)
    linhas.append("RESUMO DA AUDITORIA")
    linhas.append("=" * 48)
    linhas.append(f"Hosts analisados: {total_ips}")
    linhas.append(f"Hosts ativos: {ativos}")
    linhas.append(f"Hosts sem resposta: {sem_resposta}")
    linhas.append(
        f"Total de portas abertas: {total_abertas}"
    )
    linhas.append(
        f"Hosts com risco alto: {riscos['Alto']}"
    )
    linhas.append(
        f"Hosts com risco médio: {riscos['Médio']}"
    )
    linhas.append(
        f"Hosts com risco baixo: {riscos['Baixo']}"
    )
    linhas.append(
        "Hosts com risco indefinido: "
        f"{riscos['Indefinido']}"
    )
    linhas.append(
        f"Tempo total da auditoria: "
        f"{formatar_tempo(tempo_total)}"
    )

    print()
    print("Auditoria concluída.")
    print(
        f"Tempo total: {formatar_tempo(tempo_total)}"
    )

    return "\n".join(linhas)


def salvar_relatorio(relatorio, nome_arquivo):
    with open(
        nome_arquivo,
        "w",
        encoding="utf-8"
    ) as arquivo:
        arquivo.write(relatorio)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "NetAudit - Auditoria básica de serviços em rede"
        )
    )

    parser.add_argument(
        "ip_inicial",
        help="Primeiro endereço IPv4 da faixa",
    )

    parser.add_argument(
        "ip_final",
        help="Último endereço IPv4 da faixa",
    )

    parser.add_argument(
        "-p",
        "--portas",
        help=(
            "Portas separadas por vírgula. "
            "Exemplo: 22,80,443"
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        help=(
            "Nome do arquivo de saída. "
            "Padrão: relatorio_netaudit.txt"
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help=(
            "Tempo máximo de espera por porta, em segundos. "
            "Padrão: 1"
        ),
    )

    args = parser.parse_args()

    try:
        if args.timeout <= 0:
            raise ValueError(
                "O timeout deve ser maior que zero."
            )

        ips = gerar_ips(
            args.ip_inicial,
            args.ip_final
        )

        if args.portas:
            portas = converter_portas(args.portas)
        else:
            portas = list(PORTAS.keys())

        nome_arquivo = (
            args.output
            if args.output
            else "relatorio_netaudit.txt"
        )

        relatorio = gerar_relatorio(
            ips,
            portas,
            args.timeout
        )

        print()
        print(relatorio)

        salvar_relatorio(
            relatorio,
            nome_arquivo
        )

        print()
        print(
            f"Relatório salvo em: {nome_arquivo}"
        )

    except ipaddress.AddressValueError:
        print(
            "Erro: um dos endereços IP informados "
            "não é um IPv4 válido."
        )

    except ValueError as erro:
        print(f"Erro: {erro}")

    except OSError as erro:
        print(
            f"Erro ao salvar ou executar a auditoria: "
            f"{erro}"
        )

    except KeyboardInterrupt:
        print()
        print("Execução interrompida pelo usuário.")


if __name__ == "__main__":
    main()