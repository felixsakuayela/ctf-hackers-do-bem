<div style="text-align:center">
    <img src="new-banner2.PNG" alt="Banner" />
</div>

### DESAFIO 1: Log de Acesso - 20 pts ✅

📜 - Logs e Mais Logs!

Durante minha incursão nos sistemas da Ficticious, precisei agir rapidamente para ocultar meus rastros, assim como nos desafios anteriores. A remoção dos logs foi um desafio, dada a vastidão dos registros. No entanto, deixei alguns arquivos para você examinar. Vamos ver se você consegue identificar minha presença no sistema.

Para este e os próximos exercícios, acesse a versão online através do link que se encontra no campo Target.

Baseando-se no arquivo access.log, responda, quantas requisições foram registradas neste arquivo?

```
# Nome do arquivo
file_name = 'access.log'

# Inicializa o contador de requisições
request_count = 0

# Abre o arquivo para leitura
with open(file_name, 'r') as file:
    # Itera sobre cada linha do arquivo
    for line in file:
        # Incrementa o contador de requisições
        request_count += 1

# Imprime o número total de requisições
print("Número total de requisições no arquivo:", request_count)
```


### DESAFIO 2: Acessos Únicos - 20 pts ✅

Agora a respeito da quantidade de acessos!

Quantos IPs únicos, sem repetir, acessaram esse servidor web?

```
# Abre o arquivo de log
with open('access.log', 'r') as file:
    # Cria um conjunto para armazenar IPs únicos
    unique_ips = set()
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se existem pelo menos 4 campos na linha e se o quarto campo é um IP
        if len(fields) >= 4:
            # Adiciona o IP ao conjunto de IPs únicos
            unique_ips.add(fields[3])

# Imprime a quantidade de IPs únicos
print("Quantidade de IPs únicos:", len(unique_ips))
```



### DESAFIO 3: Arquivos Únicos - 20 pts ✅

Quantos arquivos diferentes os IPs tentaram acessar? 

A resposta é um número inteiro.

```
# Abre o arquivo de log
with open('access.log', 'r') as file:
    # Cria um conjunto para armazenar os caminhos dos arquivos únicos
    unique_files = set()
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se existem pelo menos 7 campos na linha
        if len(fields) >= 7:
            # Obtém o caminho do arquivo da linha
            file_path = fields[7]
            # Adiciona o caminho do arquivo ao conjunto de arquivos únicos
            unique_files.add(file_path)

# Imprime o número total de arquivos diferentes acessados
print("Número total de arquivos diferentes acessados:", len(unique_files))

# Imprime os arquivos diferentes acessados
print("Arquivos únicos acessados:")
for file_path in unique_files:
    print(file_path)
```



### DESAFIO 4: Endereço Específico - 20 pts ✅

📜 - Logs e Mais Logs!

Qual endereço de IP corresponde a requisição número 397 desse arquivo de log?

```
# Número da requisição desejada
numero_requisicao = 397

# Contador de linhas
contador_linhas = 0

# Endereço de IP correspondente à requisição
ip_correspondente = None

# Abre o arquivo de log
with open('access.log', 'r') as file:
    # Itera sobre cada linha do arquivo
    for line in file:
        contador_linhas += 1
        if contador_linhas == numero_requisicao:
            # Divide a linha em campos separados por espaços em branco
            fields = line.split()
            # Verifica se existem pelo menos 4 campos na linha e se o quarto campo é um IP
            if len(fields) >= 4:
                ip_correspondente = fields[3]
            break  # Interrompe o loop após encontrar a requisição desejada

# Imprime o endereço de IP correspondente à requisição
if ip_correspondente:
    print("Endereço de IP correspondente à requisição número", numero_requisicao, ":", ip_correspondente)
else:
    print("Requisição número", numero_requisicao, "não encontrada.")
```



### DESAFIO 5: Segundo! - 20 pts ✅

📜 - Logs e Mais Logs!

Qual foi o segundo exato dessa requisição 397 desse arquivo de log?

```
# Número da requisição desejada
numero_requisicao = 397

# Abre o arquivo de log
with open('access.log', 'r') as file:
    # Pula para a linha da requisição desejada
    for _ in range(numero_requisicao - 1):
        next(file)
    # Lê a linha correspondente à requisição
    line = next(file)
    # Divide a linha pelo caractere ":" para extrair a hora
    hora_requisicao = line.split(':')[3]
    # Extrai os segundos da hora da requisição
    segundos = hora_requisicao.split()[0]

# Imprime o segundo exato da requisição
print("Segundo exato da requisição número", numero_requisicao, ":", segundos)
```


### DESAFIO 6: Quantidade de requisições... - 20 pts ✅

📜 - Logs e Mais Logs!

Qual endereço IP aparece apenas uma única vez no arquivo de log?

```
from collections import Counter

# Abre o arquivo de log
with open('access.log', 'r') as file:
    # Lista para armazenar todos os IPs
    all_ips = []
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se existem pelo menos 4 campos na linha e se o quarto campo é um IP
        if len(fields) >= 4:
            # Adiciona o IP à lista de todos os IPs
            all_ips.append(fields[3])

# Conta a ocorrência de cada IP
ip_counts = Counter(all_ips)

# Imprime os IPs que aparecem apenas uma vez
print("IPs que aparecem uma única vez:")
for ip, count in ip_counts.items():
    if count == 1:
        print(ip)
```



### DESAFIO 7: Qual Arquivo? - 20 pts ✅

📜 - Logs e Mais Logs!

O endereço IP da questão anterior acessou um arquivo HTML. Qual o nome do arquivo?

Formata da resposta em caixa baixa e com a extensão: arquivo.html

```
# Define o nome do arquivo de log
nome_arquivo_log = 'access.log'

# IP específico que estamos procurando
ip_especifico = '12.43.121.114'

# Variável para armazenar o nome do arquivo, se encontrado
nome_arquivo_encontrado = None

# Abre o arquivo de log
with open(nome_arquivo_log, 'r') as arquivo_log:
    # Itera sobre cada linha do arquivo
    for linha in arquivo_log:
        # Verifica se o IP específico está presente na linha
        if ip_especifico in linha:
            # Divide a linha pelo espaço em branco
            campos = linha.split()
            # Obtém o caminho do arquivo (sexto elemento)
            caminho_arquivo = campos[7]
            # Elimina a barra do início do caminho do arquivo
            nome_arquivo = caminho_arquivo.split('/')[-1]
            # Armazena o nome do arquivo encontrado
            nome_arquivo_encontrado = nome_arquivo
            # Interrompe o loop, pois encontramos o IP específico
            break

# Se o nome do arquivo foi encontrado, imprime-o
if nome_arquivo_encontrado:
    print("Nome do arquivo acessado pelo IP específico:", nome_arquivo_encontrado)
else:
    print("O IP específico não foi encontrado no arquivo de log.")
```


### DESAFIO 8: Hora do acesso - 20 pts ✅

📜 - Logs e Mais Logs!

Qual a HORA em que esse arquivo foi solicitado por esse IP que tem somente um registro no arquivo de log?

A resposta deverá ser a hora no formato em que aparece no arquivo, por exemplo:
12:35:28

```
# Define o nome do arquivo de log
nome_arquivo_log = 'access.log'

# IP específico que estamos procurando
ip_especifico = '12.43.121.114'

# Variável para armazenar a hora da solicitação, se encontrado
hora_formatada = None

# Abre o arquivo de log
with open(nome_arquivo_log, 'r') as arquivo_log:
    # Itera sobre cada linha do arquivo
    for linha in arquivo_log:
        # Verifica se o IP específico está presente na linha
        if ip_especifico in linha:
            # Divide a linha pelo espaço em branco
            campos = linha.split()
            # Obtém a hora da solicitação (segundo elemento)
            hora_solicitacao = campos[0].split(':')[0:4]  # Pegando apenas a hora, minuto e segundo
            # Formata a hora corretamente
            hora_formatada = ':'.join(hora_solicitacao[1:4])  # Ignorando a data
            # Interrompe o loop, pois encontramos o IP específico
            break

# Se a hora da solicitação foi encontrada, imprime-a
if hora_formatada:
    print("Hora da solicitação pelo IP específico:", hora_formatada)
else:
    print("O IP específico não foi encontrado no arquivo de log.")
```



### DESAFIO 9: Campeão! - 20 pts ✅


Quantas vezes o endereço IP que mais teve requisições apareceu?

```
from collections import Counter

# Abre o arquivo de log
with open('access.log', 'r') as file:
    # Lista para armazenar todos os IPs
    all_ips = []
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se existem pelo menos 4 campos na linha e se o quarto campo é um IP
        if len(fields) >= 4:
            # Adiciona o IP à lista de todos os IPs
            all_ips.append(fields[3])

# Conta a ocorrência de cada IP
ip_counts = Counter(all_ips)

# Encontra o IP com o maior número de requisições
most_common_ip, num_requests = ip_counts.most_common(1)[0]

# Imprime a quantidade de requisições do IP com maior número de requisições
print("Número de requisições:", num_requests)
```



### DESAFIO 10: Quem é ele? - 20 pts ✅

📜 - Logs e Mais Logs!

E qual foi esse IP que mais teve requisições?

```
from collections import Counter

# Abre o arquivo de log
with open('access.log', 'r') as file:
    # Lista para armazenar todos os IPs
    all_ips = []
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se existem pelo menos 4 campos na linha e se o quarto campo é um IP
        if len(fields) >= 4:
            # Adiciona o IP à lista de todos os IPs
            all_ips.append(fields[3])

# Conta a ocorrência de cada IP
ip_counts = Counter(all_ips)

# Encontra o IP com o maior número de requisições
most_common_ip, num_requests = ip_counts.most_common(1)[0]

# Imprime o IP com o maior número de requisições
print("IP com o maior número de requisições:", most_common_ip)
```


### DESAFIO 11: File? - 20 pts ✅

📜 - Logs e Mais Logs!

Qual foi o primeiro arquivo que o IP que mais teve requisições logadas acessou?

```
from collections import Counter

# Abre o arquivo de log
with open('access.log', 'r') as file:
    # Lista para armazenar todos os IPs
    all_ips = []
    # Dicionário para mapear IPs para os arquivos que acessaram
    ip_to_files = {}
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se existem pelo menos 4 campos na linha e se o quarto campo é um IP
        if len(fields) >= 4:
            ip = fields[3]
            # Adiciona o IP à lista de todos os IPs
            all_ips.append(ip)
            # Extrai o nome do arquivo da linha
            file_name = fields[7]
            # Adiciona o nome do arquivo à lista de arquivos acessados pelo IP
            if ip in ip_to_files:
                ip_to_files[ip].append(file_name)
            else:
                ip_to_files[ip] = [file_name]

# Conta a ocorrência de cada IP
ip_counts = Counter(all_ips)

# Encontra o IP com o maior número de requisições
most_common_ip, num_requests = ip_counts.most_common(1)[0]

# Imprime os arquivos acessados pelo IP com o maior número de requisições
print("Arquivos acessados por esse IP:")


if most_common_ip in ip_to_files:
    for file_name in ip_to_files[most_common_ip]:
        print(file_name)
else:
    print("Nenhum arquivo encontrado para este IP.")
```


### DESAFIO 12: Quantos arquivos... - 20 pts ✅
📜 - Logs e Mais Logs!
Quantos arquivos diferentes esse mesmo IP com o maior número de requisições tentou acessar?

A resposta é um número inteiro.

```
# Lista de URLs com duplicatas
urls = [
    "/contact.html",
    "/contact.html",
    "/services.html",
    "/services.html",
    "/about.html",
    "/index.html",
    "/services.html",
    "/index.html",
    "/services.html",
    "/services.html",
    "/services.html",
    "/index.html",
    "/about.html",
    "/index.html"
]

# Eliminar duplicatas usando um conjunto
urls_sem_duplicatas = set(urls)

# Converter o conjunto de volta para lista se necessário
urls_sem_duplicatas = list(urls_sem_duplicatas)

# Exibir a lista sem duplicatas
print("Lista de URLs sem duplicatas:", urls_sem_duplicatas)

# Contar a quantidade de URLs únicos
quantidade_urls_unicos = len(urls_sem_duplicatas)

# Exibir a quantidade de URLs únicos
print("Quantidade de URLs únicos:", quantidade_urls_unicos)
```


### DESAFIO 13: Acesso Indevido - 20 pts ✅

📜 - Logs e Mais Logs!

Durante minha tentativa de acesso ao sistema, o Suricata, uma ferramenta de detecção e prevenção de intrusões (IDS/IPS), foi acionado repetidamente, capturando cada uma das minhas ações. O Suricata desempenha um papel crucial em ambientes de rede, monitorando o tráfego e identificando atividades suspeitas. Sua capacidade de registrar e alertar sobre potenciais ameaças é vital para manter a integridade e segurança do sistema.

Para os próximos desafios, acesse o arquivo de log que se encontra no link no campo Alvo.

Com base nos registros do Suricata, responda, qual o endereço IP foi o alvo principal das minhas tentativas de acesso?

```
from collections import Counter

# Abre o arquivo de log
with open('suricata.log', 'r') as file:
    # Lista para armazenar todos os IPs de destino
    dest_ips = []
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se a linha possui campos suficientes
        if len(fields) >= 8:
            # Extrai o endereço IP de destino da linha
            dest_ip = fields[10]
            # Adiciona o endereço IP à lista de IPs de destino
            dest_ips.append(dest_ip)

# Conta a ocorrência de cada endereço IP de destino
ip_counts = Counter(dest_ips)

# Encontra o endereço IP com o maior número de tentativas de acesso
most_common_ip, num_attempts = ip_counts.most_common(1)[0]

# Imprime o endereço IP que foi o alvo principal das tentativas de acesso
print("Endereço IP alvo principal das tentativas de acesso:", most_common_ip)
```


### DESAFIO 14: Quantidade Indevida - 20 pts ✅

📜 - Logs e Mais Logs!

Qual o total das requisições que foram logadas pelo Suricata?

A resposta é um número inteiro.

```
from collections import Counter

# Abre o arquivo de log
with open('suricata.log', 'r') as file:
    # Lista para armazenar todos os IPs de destino
    dest_ips = []
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se a linha possui campos suficientes
        if len(fields) >= 8:
            # Extrai o endereço IP de destino da linha
            dest_ip = fields[10]
            # Adiciona o endereço IP à lista de IPs de destino
            dest_ips.append(dest_ip)

# Conta a ocorrência de cada endereço IP de destino
total_requests = len(dest_ips)

# Imprime o total de requisições logadas pelo Suricata
print("Total de requisições logadas pelo Suricata:", total_requests)
```


### DESAFIO 15: IPs Únicos - 20 pts ✅


Quantos IPs únicos que utilizei no meu ataque foram identificados pelo Suricata no campo SRC?

```
# Abre o arquivo de log
with open('suricata.log', 'r') as file:
    # Conjunto para armazenar todos os IPs de origem únicos
    src_ips = set()
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se a linha possui campos suficientes
        if len(fields) >= 8:
            # Extrai o endereço IP de origem da linha
            src_ip = fields[5]
            # Adiciona o endereço IP ao conjunto de IPs de origem
            src_ips.add(src_ip)

# Imprime a quantidade de IPs de origem únicos identificados pelo Suricata
print("Quantidade de IPs únicos identificados pelo Suricata no campo SRC:", len(src_ips))
```


### DESAFIO 16: Maliciosas - 20 pts ✅

📜 - Logs e Mais Logs!

Quantos tipos diferentes de atividades maliciosas o Suricata conseguiu identificar?

Novamente, a reposta é numérica!

```
# Abre o arquivo de log
with open('suricata.log', 'r') as file:
    # Conjunto para armazenar todos os tipos de alertas únicos
    alert_types = set()
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se a linha possui campos suficientes
        if len(fields) >= 6:
            # Extrai o tipo de alerta da linha (remove os colchetes)
            alert_type = fields[4][1:-1]
            # Adiciona o tipo de alerta ao conjunto de tipos de alertas
            alert_types.add(alert_type)

# Imprime a quantidade de tipos diferentes de atividades maliciosas identificadas pelo Suricata
print("Quantidade de tipos diferentes de atividades maliciosas identificadas pelo Suricata:", len(alert_types))
```



### DESAFIO 17: Quantos Dias? - 20 pts ✅

📜 - Logs e Mais Logs!

Em quantos dias diferentes foram realizados os ataques?

A resposta é um número inteiro.

```
# Abre o arquivo de log
with open('suricata.log', 'r') as file:
    # Conjunto para armazenar todas as datas únicas dos ataques
    attack_dates = set()
    
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se a linha possui campos suficientes
        if len(fields) >= 1:
            # Extrai a data do ataque da linha
            attack_date = fields[0]
            # Adiciona a data do ataque ao conjunto de datas de ataques
            attack_dates.add(attack_date)

# Imprime a quantidade de dias diferentes em que os ataques foram realizados
print("Quantidade de dias diferentes em que os ataques foram realizados:", len(attack_dates))
```


### DESAFIO 18: SQLi - 20 pts ✅


Quantas requisições de SQL Injection foram identificadas pelo Suricata?

A resposta é um número inteiro.

```
# Variável para armazenar a contagem de SQL Injections
sql_injection_count = 0

# Conjunto para armazenar os tipos diferentes de atividades maliciosas identificadas
alert_types = set()

# Abre o arquivo de log
with open('suricata.log', 'r') as file:
    # Itera sobre cada linha do arquivo
    for line in file:
        # Divide a linha em campos separados por espaços em branco
        fields = line.split()
        # Verifica se a linha possui campos suficientes
        if len(fields) >= 6:
            # Extrai o tipo de alerta da linha (remove os colchetes)
            alert_type = fields[4][1:-1]
            # Adiciona o tipo de alerta ao conjunto de tipos de alertas
            alert_types.add(alert_type)
            # Verifica se o tipo de alerta é "SQL Injection"
            if alert_type == "QLInjectio":
                # Incrementa o contador de SQL Injection
                sql_injection_count += 1

# Imprime o número total de SQL Injections identificadas pelo Suricata
print("Número total de SQL Injections identificadas pelo Suricata:", sql_injection_count)

# Imprime os tipos diferentes de atividades maliciosas identificadas como "SQL Injection"
print("Tipos diferentes de atividades maliciosas identificadas como SQL Injection:")
for alert_type in alert_types:
    print(alert_type)
```


### DESAFIO 19: Auth? - 20 pts ✅


Ao me infiltrar em um dos servidores internos do Ficticious Bank, foi crucial ocultar minha presença, assim como em operações anteriores.

Para garantir que não haveria rastros, eliminei o arquivo localizado em /var/log/auth.log. Este arquivo é vital, pois registra atividades relacionadas à autenticação em máquinas Linux.

Aqui está um exemplo de uma das entradas desse arquivo:

[...snip...]
mai 12 14:20:19 localhost systemd[187735]: Accepted publickey for user from 192.168.88.5
[...snip...]

Para esclarecer, vou detalhar o significado de cada segmento:

mai 12 14:20:19: Representa a data e hora do evento.

systemd[187735]: Indica o processo e seu PID (Process ID) associado à tentativa.

Accepted publickey: Mostra se a solicitação foi aceita ou negada e o método de autenticação utilizado.

192.168.88.5: É o IP de origem da tentativa de autenticação.

Com base nesses detalhes e no arquivo de log que disponibilizei, acesse a versão online no link que se encontra no campo Target, responda:

Quantas tentativas de acesso foram registradas neste arquivo de log?

A resposta é um número inteiro.

```
# Caminho para o arquivo de log
caminho_arquivo = 'auth.log'

# Contador de tentativas de acesso
tentativas_acesso = 0

# Abre o arquivo de log
with open(caminho_arquivo, 'r') as arquivo:
    # Conta o número total de linhas no arquivo
    for linha in arquivo:
        # Incrementa o contador de tentativas de acesso
        tentativas_acesso += 1

# Imprime o número de tentativas de acesso registradas no arquivo de log
print("Número de tentativas de acesso registradas:", tentativas_acesso)
```


### DESAFIO 20: Tipos de Autenticação - 20 pts ✅

Ainda utilizando o arquivo de log anterior. Quantos tipos diferentes de autenticação foram logados nesse extrato?

abr 28 05:27:19 localhost systemd[187735]: Failed smartcard for user from 10.0.1.1

Nesse caso o "tipo" foi smartcard... Assim por diante.

```
# Caminho para o arquivo de log
caminho_arquivo = 'auth.log'

# Conjunto para armazenar tuplas de (endereço IP, tipo de autenticação) únicas
ips_tipos_autenticacao_unicos = set()

# Abre o arquivo de log
with open(caminho_arquivo, 'r') as arquivo:
    # Itera sobre cada linha do arquivo
    for linha in arquivo:
        # Divide a linha em campos separados por espaço
        campos = linha.split()
        # Extrai o tipo de autenticação da linha
        tipo_autenticacao = campos[6]
        # Extrai o endereço IP da linha
        ip = campos[-1]
        # Adiciona a tupla (endereço IP, tipo de autenticação) ao conjunto de tuplas únicas
        ips_tipos_autenticacao_unicos.add((ip, tipo_autenticacao))

# Conta o número de tipos diferentes de autenticação
num_tipos_autenticacao = len(ips_tipos_autenticacao_unicos)

# Imprime os tipos diferentes de autenticação
print("Tipos diferentes de autenticação logados:")
for ip, tipo_autenticacao in ips_tipos_autenticacao_unicos:
    print(f"{tipo_autenticacao}")
# Imprime o número de tipos diferentes de autenticação logados no arquivo
print("Número de tipos diferentes de autenticação logados:", num_tipos_autenticacao)
```


### DESAFIO 21: Processos? - 20 pts ✅

📜 - Logs e Mais Logs!

Quantos processos diferentes logaram tentativas de acesso nesse servidor?

Considerando apenas os nomes dos processos, não seus respectivos PIDs.

```
# Caminho para o arquivo de log
caminho_arquivo = 'auth.log'

# Conjunto para armazenar nomes de processos únicos
processos_unicos = set()

# Abre o arquivo de log
with open(caminho_arquivo, 'r') as arquivo:
    # Itera sobre cada linha do arquivo
    for linha in arquivo:
        # Divide a linha em campos separados por espaço
        campos = linha.split()
        # Verifica se a linha contém "Failed" e extrai o nome do processo
        if "Failed" in campos:
            indice_failed = campos.index("Failed")
            nome_processo = campos[indice_failed - 1].split("[")[0]
            processos_unicos.add(nome_processo)
        # Verifica se a linha contém "Accepted" e extrai o nome do processo
        elif "Accepted" in campos:
            indice_accepted = campos.index("Accepted")
            nome_processo = campos[indice_accepted - 1].split("[")[0]
            processos_unicos.add(nome_processo)

# Conta o número de processos diferentes
num_processos_diferentes = len(processos_unicos)

# Imprime o número de processos diferentes que logaram tentativas de acesso
print("Número de processos diferentes que logaram tentativas de acesso:", num_processos_diferentes)
```



### DESAFIO 22: Processos? - 20 pts ✅

📜 - Logs e Mais Logs!

Quantos processos diferentes logaram tentativas de acesso nesse servidor?

Considerando apenas os nomes dos processos, não seus respectivos PIDs.

```
# Lista de serviços
servicos = [
    "certificate",
    "smartcard",
    "keyboard-interactive",
    "password",
    "publickey",
    "otp",
    "keyboard-interactive",
    "keyboard-interactive",
    "publickey",
    "smartcard",
    "password",
    "keyboard-interactive",
    "keyboard-interactive",
    "otp",
    "keyboard-interactive",
    "publickey",
    "password",
    "certificate",
    "publickey",
    "smartcard",
    "publickey",
    "publickey",
    "password",
    "smartcard",
    "publickey",
    "otp",
    "certificate",
    "password",
    "password",
    "otp",
    "smartcard",
    "keyboard-interactive",
    "password",
    "certificate",
    "otp",
    "password",
    "password",
    "smartcard",
    "smartcard",
    "keyboard-interactive",
    "publickey",
    "certificate",
    "otp",
    "otp",
    "certificate",
    "smartcard",
    "smartcard",
    "publickey",
    "smartcard",
    "otp",
    "keyboard-interactive",
    "otp",
    "certificate",
    "password",
    "otp",
    "certificate",
    "keyboard-interactive",
    "publickey",
    "certificate",
    "certificate"
]

# Converter a lista em um conjunto para eliminar duplicatas
servicos_unicos = set(servicos)

# Contar o número de serviços únicos
num_servicos_unicos = len(servicos_unicos)

# Imprimir o número de serviços únicos
print("Número de serviços únicos:", num_servicos_unicos)
```



### DESAFIO 23: 1º de Maio - 20 pts ✅

📜 - Logs e Mais Logs!

Quantas tentativas de acesso aconteceram no dia 1º de Maio?

```
# Caminho para o arquivo de log
caminho_arquivo = 'auth.log'

# Contador para armazenar o número de tentativas de acesso
tentativas_maio_01 = 0

# Abre o arquivo de log
with open(caminho_arquivo, 'r') as arquivo:
    # Itera sobre cada linha do arquivo
    for linha in arquivo:
        # Verifica se a linha contém "mai 01"
        if "mai 01" in linha:
            # Incrementa o contador de tentativas
            tentativas_maio_01 += 1

# Imprime o número de tentativas de acesso no dia 1º de maio
print("Número de tentativas de acesso no dia 1º de maio:", tentativas_maio_01)
```
