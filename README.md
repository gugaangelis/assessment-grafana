# Guia de Execução - Assessment Grafana

> Guia de execução e troubleshooting para o time de suporte.
> Script: [grafana_assessment.py](grafana_assessment.py) · Compatível com Grafana **9.x a 12.x** (OSS e Enterprise) · Python **3.8+**

---

## 1. Objetivo

Ferramenta de **assessment somente leitura** de um ambiente Grafana. Ela se conecta à HTTP API, levanta o que existe no ambiente (instância, organizações, pastas, dashboards, fontes de dados, regras de alerta, notificação, usuários, tokens, compartilhamentos), compara com boas práticas de observabilidade/SRE e gera relatórios para engenharia e liderança.

A avaliação é organizada em **5 pilares** e 18 domínios (~85 controles):

| Pilar | Domínios avaliados |
|---|---|
| Confiabilidade da plataforma | Versões & ciclo de vida · Alta disponibilidade · Desempenho & carga · Retenção & housekeeping |
| Cobertura de observabilidade | Fontes de dados · Sinais & correlação · Dashboards & padronização · Adoção & uso |
| Qualidade de alertas | Regras de alerta · Ruído & flapping · Alertas em aberto |
| Resposta e operação | Notificações & roteamento · Integrações (ITSM/on-call) · Silêncios & manutenção · Runbooks & contexto |
| Segurança e governança | Identidade & acesso · Exposição & criptografia · Permissões & auditoria |

### Garantia de somente leitura

- O cliente HTTP do script **só implementa GET** e só em caminhos `/api/...`. Proxy de fonte de dados (`/api/datasources/proxy`), `/api/ds/*` e recursos de plugin são bloqueados **antes** de sair da máquina (`PermissionError`). Não existe código de POST/PUT/PATCH/DELETE.
- Autenticação por usuário/senha usa **HTTP Basic** em cada chamada: não cria sessão, não há logout a fazer.
- **Único efeito colateral:** o health check das fontes de dados (`GET /api/datasources/uid/<uid>/health`) executa a consulta de teste de cada fonte (a mesma do botão *Save & test*, sem salvar). Para não executar: `--skip-ds-health`.
- O Grafana OSS **não tem** papel de administrador somente leitura; por isso a garantia de read-only é do script. O script **não altera nada** no Grafana, nem grava arquivos fora da pasta de saída.

---

## 2. Pré-requisitos

| Item | Detalhe |
|---|---|
| Python | 3.8 ou superior (`python3 --version` / `py --version`) |
| Bibliotecas para a coleta | **Nenhuma**: usa só a biblioteca padrão. Roda em jump server sem internet/pip. |
| Bibliotecas opcionais (PDF/PPTX) | `pip install --user reportlab python-pptx`. Sem elas, PDF e PPTX são **pulados** (o restante é gerado normalmente). |
| Rede | Acesso HTTPS da máquina de execução até o Grafana. Normalmente via jump server ou VPN. |
| Credencial | Usuário/senha com as permissões da seção 3 (recomendado) **ou** service account token (cobertura parcial). |

---

## 3. Preparação da credencial no Grafana (feita pelo administrador do cliente)

Ambiente Assaí: **URL** `https://grafana.corp.assai.com.br/` · **usuário** `vertare`.

| Configuração | Valor | Para quê |
|---|---|---|
| Grafana Admin (server admin) | **Sim** (*Administration → Users → vertare → Grafana Admin*) | Configuração do servidor (`/api/admin/settings`), estatísticas, usuários e lista de organizações |
| Papel em cada organização avaliada | **Admin** (*Administration → Users → vertare → Organizations*) | Fontes de dados, alerting (contact points, políticas, silêncios), usuários da org, times, service accounts, permissões de pastas |
| Basic auth | `[auth.basic] enabled = true` (padrão) | Login por usuário/senha na API |
| Tipo de conta | Local ou LDAP | Conta só OAuth/SAML (Entra ID, Okta…) **não** autentica por Basic auth |

- O usuário precisa ser **membro** de cada organização a avaliar: o script lê uma org por vez com o header `X-Grafana-Org-Id`. Organizações em que ele não é membro aparecem como "sem acesso" no relatório.
- **Grafana Enterprise/Cloud:** em vez de Admin, pode-se criar uma role RBAC customizada só com ações `*:read` (datasources:read, alert.*:read, users:read, teams:read, serviceaccounts:read, settings:read, server.stats:read, folders.permissions:read…).
- Recomendação: conta **exclusiva** para o assessment, **desabilitada ao final** (seção 10).

> Com papel **Editor** ou **Viewer**, ou sem Grafana Admin, o assessment roda, mas os coletores restritos aparecem como **"parcial"** no apêndice do relatório e os controles dependentes ficam **N/A** (não penalizam o score, mas reduzem a cobertura da análise).

> ⚠️ **Brute force:** o Grafana bloqueia o login após **5 senhas erradas em 5 minutos**. O script valida a credencial com **uma** chamada antes de qualquer paralelismo e para no primeiro HTTP 401. Se der 401, confira a senha antes de tentar de novo.

### Alternativa: service account token

`GRAFANA_TOKEN` com um token de service account (papel Admin) funciona, mas service accounts não podem ser Grafana Admin e valem para **uma** organização: a configuração do servidor, os usuários globais e as outras orgs ficam N/A. Use só se a conta de usuário não for possível.

---

## 4. Execução passo a passo

### 4.1 Definir as variáveis de ambiente

Prefira variáveis de ambiente a parâmetros na linha de comando, e **não defina a senha em variável**: o script pede no prompt, sem exibi-la.

**Linux / jump server (bash):**
```bash
export GRAFANA_URL='https://grafana.corp.assai.com.br/'
export GRAFANA_USER='vertare'
# senha: o script pede no prompt (recomendado). Alternativa: read -rs GRAFANA_PASSWORD && export GRAFANA_PASSWORD
```

**Windows (PowerShell):** ver o guia completo na [seção 5](#5-execução-no-windows-powershell).
```powershell
$env:GRAFANA_URL  = 'https://grafana.corp.assai.com.br/'
$env:GRAFANA_USER = 'vertare'
```

> A URL é a mesma do navegador (raiz do Grafana). Se o Grafana estiver publicado em subcaminho (ex.: `https://host/grafana/`), use a URL com o subcaminho.

### 4.2 Testar conexão e permissões (sempre fazer primeiro)

**bash:**
```bash
python3 grafana_assessment.py --test
```

**PowerShell:**
```powershell
py .\grafana_assessment.py --test
```

Saída esperada (exemplo):
```
Conectado: https://grafana.corp.assai.com.br
Versão: 11.6.1 (Open Source) · suporte limitado · autenticação: usuario_senha · banco: ok
Usuário: vertare · Grafana Admin (server admin): sim
  org 1: Main Org. · papel Admin
Endpoints (org atual 1):
  /api/user                                            OK  · identidade do usuário
  /api/admin/settings                                  OK  · config do servidor · requer Grafana Admin
  /api/datasources                                     OK  (12 itens)  · fontes de dados · requer Admin da org
  ...
  /api/v1/sso-settings                                 OK  · SSO (11.x+)
```

- `OK` → endpoint acessível.
- `n/a` (HTTP 404) → normal: o endpoint não existe naquela versão/edição ou o recurso está desabilitado.
- `NEGADO` (HTTP 401/403) → falta permissão. Ajustar o usuário (seção 3) **antes** de seguir, ou seguir ciente de que parte da análise ficará parcial.
- Linha `<- recomendado Admin` ao lado de uma org → o usuário não é Admin naquela organização.

### 4.3 Rodar o assessment

**bash:**
```bash
python3 grafana_assessment.py --customer "Assaí Atacadista" --env-name "Produção" --days 30 --expected-integrations zabbix
```

**PowerShell:**
```powershell
py .\grafana_assessment.py --customer "Assaí Atacadista" --env-name "Produção" --days 30 --expected-integrations zabbix
```

Durante a execução o progresso é exibido com horário (`[HH:MM:SS] [Main Org.] fontes de dados...`, `pastas e dashboards...`, `histórico de estados de alerta (30 dias)...` etc.). Ao final:

```
[16:42:10] Pilares: Confiabilidade da plataforma 62 · Cobertura de observabilidade 71 · ...
[16:42:10] Concluído: score 64/100 · 812 chamadas de leitura · saída em /home/user/grafana-assessment-20261126-1640
```

### 4.4 Cenários comuns

| Cenário | Comando |
|---|---|
| Certificado interno / self-signed | `--ca-bundle /caminho/ca.pem` (preferível) ou `--insecure` |
| Proxy HTTP corporativo atrapalhando o acesso via VPN | `--no-proxy` |
| Jump server sem `reportlab`/`python-pptx` | `--formats none` (depois gerar PDF/PPTX em outra máquina, ver 4.5) |
| Avaliar só algumas organizações | `--orgs "Main Org.,NOC*"` (nome com curinga ou ID) |
| Não executar o health check das fontes | `--skip-ds-health` |
| Muitos dashboards / API lenta | `--max-dashboards 2000`, `--timeout 120` e manter `--threads 4` (ou reduzir para 2) |
| Validar integrações esperadas | `--expected-integrations zabbix,servicenow,teams` |
| Pasta de saída específica | `--out ./saida-assai` |

Os parâmetros são os mesmos nos dois shells; muda só a forma de chamar o Python e a quebra de linha (`\` no bash, `` ` `` no PowerShell, sem espaço depois).

Exemplo combinado (jump server com CA interna, sem proxy e sem PDF/PPTX):

**bash:**
```bash
python3 grafana_assessment.py --insecure --no-proxy --formats none \
  --customer "Assaí Atacadista" --env-name "Produção" --days 30 --expected-integrations zabbix
```

**PowerShell:**
```powershell
py .\grafana_assessment.py --insecure --no-proxy --formats none `
  --customer "Assaí Atacadista" --env-name "Produção" --days 30 --expected-integrations zabbix
```

Exemplos por cenário:

| Cenário | bash | PowerShell |
|---|---|---|
| CA interna | `python3 grafana_assessment.py --ca-bundle /certs/ca.pem` | `py .\grafana_assessment.py --ca-bundle C:\certs\ca.pem` |
| Só algumas orgs | `python3 grafana_assessment.py --orgs "Main Org.,NOC*"` | `py .\grafana_assessment.py --orgs "Main Org.,NOC*"` |
| Sem health check | `python3 grafana_assessment.py --skip-ds-health` | `py .\grafana_assessment.py --skip-ds-health` |
| Ambiente grande | `python3 grafana_assessment.py --max-dashboards 2000 --timeout 120 --threads 2` | `py .\grafana_assessment.py --max-dashboards 2000 --timeout 120 --threads 2` |
| Pasta de saída | `python3 grafana_assessment.py --out ./saida-assai` | `py .\grafana_assessment.py --out .\saida-assai` |

### 4.5 Gerar PDF/PPTX fora do jump server (`--render-only`)

1. No jump server, coletar sem PDF/PPTX: `--formats none`.
2. Copiar a pasta de saída (ou só o `dados.json`) para a sua máquina, por canal aprovado.
3. Na sua máquina (com `pip install --user reportlab python-pptx`):

   **bash:**
   ```bash
   python3 grafana_assessment.py --render-only ./grafana-assessment-20261126-1600/dados.json --customer "Assaí Atacadista"
   ```

   **PowerShell:**
   ```powershell
   py .\grafana_assessment.py --render-only .\grafana-assessment-20261126-1600\dados.json --customer "Assaí Atacadista"
   ```
   Não conecta no Grafana. Regera **todos** os arquivos (HTML, CSV, PDF, PPTX) na mesma pasta do JSON (ou em `--out`).

> Informe `--customer` novamente no `--render-only`: o nome do cliente não é lido do `dados.json`. O nome do ambiente (`--env-name`) já fica gravado no JSON.

---

## 5. Execução no Windows (PowerShell)

Os comandos funcionam no **Windows PowerShell 5.1** e no **PowerShell 7+** (`pwsh`).

### 5.1 Verificar o Python e instalar as bibliotecas opcionais

```powershell
py --version                  # launcher do Python (instalação padrão do python.org)
python --version              # alternativa, se o comando 'py' não existir
py -m pip install --user reportlab python-pptx     # opcional: só para PDF/PPTX
```

### 5.2 Ir para a pasta do script

```powershell
Set-Location C:\caminho\assessment-grafana
Get-ChildItem .\grafana_assessment.py
```

### 5.3 Registrar as variáveis de ambiente

As variáveis `$env:` valem **só para a janela atual** do PowerShell.

```powershell
$env:GRAFANA_URL  = 'https://grafana.corp.assai.com.br/'
$env:GRAFANA_USER = 'vertare'
# não defina GRAFANA_PASSWORD: o script pede a senha no prompt, sem exibi-la
```

Se precisar da senha em variável (ex.: execução agendada), leia sem exibir:
```powershell
$sec = Read-Host 'Senha do Grafana' -AsSecureString
$env:GRAFANA_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
Remove-Variable sec
```

> ⚠️ **Nunca digite a senha direto no comando** (`$env:GRAFANA_PASSWORD = 'abc...'`): o PowerShell grava os comandos no histórico (`(Get-PSReadLineOption).HistorySavePath`). O que é digitado no `Read-Host` não é gravado.

**CA interna** (alternativa ao `--insecure`):
```powershell
$env:GRAFANA_CA_BUNDLE = 'C:\certs\ca-interna.pem'
```

**Conferir o que está definido** (sem mostrar valores):
```powershell
Get-ChildItem Env:GRAFANA_* | Select-Object Name, @{n='Definida'; e={[bool]$_.Value}}
```

### 5.4 Testar conexão e permissões

```powershell
py .\grafana_assessment.py --test
```

Interpretação da saída: ver [seção 4.2](#42-testar-conexão-e-permissões-sempre-fazer-primeiro).

### 5.5 Executar o assessment

```powershell
py .\grafana_assessment.py --customer "Assaí Atacadista" --env-name "Produção" --days 30 --expected-integrations zabbix
```

**Parâmetros em uma lista** (evita problemas com a crase de continuação):
```powershell
$params = @(
  '--customer', 'Assaí Atacadista'
  '--env-name', 'Produção'
  '--days', '30'
  '--expected-integrations', 'zabbix'
  '--formats', 'none'
)
py .\grafana_assessment.py @params
```

**Salvar o log em arquivo** (PowerShell 7+):
```powershell
py .\grafana_assessment.py --customer "Assaí Atacadista" 2>&1 | Tee-Object -FilePath .\assessment.log
```

### 5.6 Abrir, regerar e empacotar o resultado

```powershell
$out = Get-ChildItem -Directory .\grafana-assessment-* | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Invoke-Item (Join-Path $out.FullName 'relatorio.html')   # abre o relatório no navegador
py .\grafana_assessment.py --render-only (Join-Path $out.FullName 'dados.json') --customer "Assaí Atacadista"
Compress-Archive -Path $out.FullName -DestinationPath "$($out.FullName).zip"
```

### 5.7 Diagnóstico de rede

```powershell
Test-NetConnection grafana.corp.assai.com.br -Port 443        # porta HTTPS alcançável?
Resolve-DnsName grafana.corp.assai.com.br                     # DNS resolve?
Get-ChildItem Env: | Where-Object Name -match 'proxy'         # há proxy no ambiente? (se sim, testar --no-proxy)

# chamada anônima (não usa credencial): deve retornar {"database":"ok", ...}
Invoke-RestMethod -Uri "$($env:GRAFANA_URL.TrimEnd('/'))/api/health"
```

- No PowerShell 7+, com certificado de CA interna, adicione `-SkipCertificateCheck` ao `Invoke-RestMethod`.

### 5.8 Limpeza ao final

```powershell
Remove-Item Env:GRAFANA_PASSWORD, Env:GRAFANA_TOKEN, Env:GRAFANA_USER, Env:GRAFANA_URL, Env:GRAFANA_CA_BUNDLE -ErrorAction SilentlyContinue
# após copiar o resultado, apague a saída da máquina (confira o caminho antes)
Remove-Item -Recurse -Force $out.FullName
Remove-Item -Force "$($out.FullName).zip" -ErrorAction SilentlyContinue
```

---

## 6. Referência de parâmetros

| Parâmetro | Variável de ambiente | Padrão | Descrição |
|---|---|---|---|
| `--url` | `GRAFANA_URL` | — | URL do Grafana (a mesma do navegador). Obrigatório (exceto `--render-only`). |
| `--user` | `GRAFANA_USER` | — | Usuário; senha via `GRAFANA_PASSWORD` ou prompt (recomendado). |
| `--token` | `GRAFANA_TOKEN` | — | Service account token (alternativa; cobertura parcial). Tem prioridade sobre `--user`. |
| `--ca-bundle` | `GRAFANA_CA_BUNDLE` | — | Arquivo PEM da CA interna. |
| `--insecure` | — | desligado | Não valida o certificado TLS. |
| `--no-proxy` | — | desligado | Ignora `HTTP(S)_PROXY` do ambiente. |
| `--timeout` | — | `60` | Timeout por chamada à API (segundos). |
| `--customer` | — | `Assaí Atacadista` | Nome do cliente exibido nos relatórios. |
| `--env-name` | — | `Produção` | Nome do ambiente exibido nos relatórios. |
| `--orgs` | — | todas do usuário | Organizações por nome (curingas `*`, `?`) ou ID, separadas por vírgula. |
| `--days` | — | `30` | Janela do histórico de estados de alerta (1 a 365). |
| `--max-events-per-day` | — | `5000` | Limite de transições de alerta lidas por dia e por org. |
| `--max-dashboards` | — | `0` (todos) | Analisa no máximo N dashboards por org (ambientes muito grandes). |
| `--skip-ds-health` | — | desligado | Não executa o health check das fontes de dados. |
| `--expected-integrations` | — | vazio | Integrações que o cliente diz ter (ex.: `zabbix,servicenow`); vira um check por item (procura em fontes, plugins e contact points). |
| `--threads` | — | `4` | Chamadas paralelas à API. Aumente com cautela. |
| `--out` | — | `grafana-assessment-AAAAMMDD-HHMM` | Pasta de saída. |
| `--formats` | — | `pdf,pptx` | Saídas extras: `pdf`, `pptx` ou `none`. HTML/CSV/JSON são sempre gerados. |
| `--test` | — | — | Só testa conexão e permissões e sai. |
| `--render-only` | — | — | Caminho de um `dados.json`; regera os relatórios sem conectar no Grafana. |

---

## 7. Arquivos gerados

Todos na pasta de saída (padrão `./grafana-assessment-AAAAMMDD-HHMM/`). CSVs usam `;` como separador e UTF-8 com BOM (abrem direto no Excel em pt-BR).

| Arquivo | Público | Conteúdo |
|---|---|---|
| `relatorio.html` | Stakeholders | Relatório completo: score global e por pilar, achados, inventário, apêndice de coleta. |
| `relatorio_executivo.pdf` | Liderança | Resumo executivo (requer `reportlab`). |
| `relatorio_tecnico.pdf` | Engenharia | Detalhamento técnico, A4 paisagem (requer `reportlab`). |
| `apresentacao_stakeholders.pptx` | Reunião de apresentação | 16:9, 14 slides, gráficos nativos editáveis e notas do apresentador (requer `python-pptx`). |
| `achados.csv` | Backlog | Lacunas por pilar, ordenadas por prioridade, com evidência, impacto e recomendação. |
| `inventario_dashboards.csv` | Engenharia | Dashboard × pasta, painéis, consultas, painéis descontinuados, refresh, fontes usadas/inexistentes, provisionado, idade. |
| `fontes_dados.csv` | Engenharia | Fonte × tipo, sinal (métricas/logs/traces), health check, uso em dashboards e regras, TLS. |
| `regras_alerta.csv` | Engenharia | Regra × intervalo, `for`, severidade, estado, saúde/erro, instâncias disparando, runbook. |
| `cobertura_pastas.csv` | Engenharia | Pasta × dashboards com tag, sem descontinuado, sem fonte quebrada, mantidos, refresh, como código. |
| `top_regras.csv` | Engenharia | Regras que mais dispararam na janela, com MTTR mediano e flag de flapping. |
| `higiene_otimizacao.csv` | Engenharia | Dashboards, fontes, regras, contact points, silêncios, usuários e tokens a tratar, com consultas/min antes/depois. |
| `dados.json` | Interno | Dados brutos + checks, scores por domínio/pilar e score global. Base para `--render-only`. |

> ⚠️ **Os arquivos são confidenciais.** Contêm nomes de dashboards, pastas, fontes de dados (com URL), logins de usuários inativos, nomes de service accounts/tokens e topologia do cliente. **Nenhuma senha ou segredo é coletado** (o Grafana mascara segredos na API e o script não lê `secureJsonData`). Tratar conforme a política de dados do cliente e apagar do jump server após a cópia.

---

## 8. Como ler o resultado

### Score

- Cada controle (check) tem prioridade **Alta (peso 3)**, **Média (peso 2)** ou **Baixa (peso 1)**.
- Score = soma dos pesos dos controles atendidos ÷ soma dos pesos avaliados × 100. Calculado por domínio, por pilar e global.
- Controles **N/A** (versão não suporta, coletor sem permissão, sem dados suficientes) **não entram** no cálculo.

| Score | Nível de maturidade |
|---|---|
| < 40 | Inicial |
| 40 – 64 | Em desenvolvimento |
| 65 – 84 | Estruturado |
| ≥ 85 | Otimizado |

### Apêndice de coleta (status por coletor)

| Status | Significado | Ação |
|---|---|---|
| `ok` | Coletado normalmente. | — |
| `n/a (endpoint inexistente...)` | Recurso não existe na versão/edição ou está desabilitado. | Nenhuma; é esperado. |
| `parcial: HTTP 403 ...` | O usuário não tem permissão nesse endpoint. | Ver seção 3 e rodar `--test`. |
| `parcial: erro ...` | Erro de rede/timeout em parte das chamadas. | Aumentar `--timeout`, reduzir `--threads`, repetir. |
| `não executado` | Não havia objetos a consultar (ex.: nenhuma pasta). | — |

Um coletor com falha **não derruba** o assessment: ele é registrado como parcial e o restante continua.

### Pontos de atenção na interpretação

- **Ruído, flapping e MTTR** vêm do histórico de estados de alerta gravado como anotações (padrão do Grafana). Se o state history estiver configurado só em **Loki** ou desabilitado, esses controles ficam N/A. Se algum dia atingir `--max-events-per-day`, os números são uma amostra.
- **Consultas/min (DE/PARA)** é uma estimativa pela configuração: regras = consultas × 60 ÷ intervalo de avaliação; dashboards = consultas × 60 ÷ refresh, **por tela aberta** (a carga real multiplica pelo número de telas, ex.: TVs de NOC).
- **Fonte inexistente** só é avaliada quando o usuário consegue ler as fontes de dados da org; dashboards que usam variável de datasource (`${ds}`) não são marcados.
- **Angular:** desabilitado por padrão no Grafana 11 e removido no 12. Painéis `graph`, `singlestat`, `table-old` e plugins Angular aparecem como descontinuados; a prioridade sobe para Alta a partir do 11.
- **Ciclo de vida da versão:** a regra está embutida no script (constantes `CURRENT_MAJOR` e `LAST_MINOR`): major vigente = suporte completo; última minor do major anterior = limitado; o resto = EOL. Quando o Grafana tem acesso a grafana.com, a versão mais recente informada pela instância é usada. **Revisar as constantes a cada novo major do Grafana.**
- **Usuário que roda o assessment:** como Grafana Admin, a própria conta `vertare` entra na contagem de Grafana Admins e de contas locais.

---

## 9. Troubleshooting

| Mensagem | Causa provável | Solução |
|---|---|---|
| `informe --url ou GRAFANA_URL` | URL não definida. | Exportar `GRAFANA_URL` ou passar `--url`. |
| `informe GRAFANA_USER (usuário/senha) ou GRAFANA_TOKEN` | Nenhuma credencial definida. | Exportar `GRAFANA_USER`. Em PowerShell, conferir com `$env:GRAFANA_USER`. |
| `Erro TLS: ... Use --ca-bundle <ca.pem> ou --insecure.` | Certificado de CA interna/self-signed. | Pedir o PEM da CA ao cliente e usar `--ca-bundle`; em último caso `--insecure`. |
| `Sem conexão com ...: <motivo>` | VPN, rota, DNS, firewall ou proxy. | Testar `curl -k <URL>/api/health` da mesma máquina (Windows: [seção 5.7](#57-diagnóstico-de-rede)); se houver `HTTPS_PROXY`, usar `--no-proxy`. |
| `Credencial recusada pelo Grafana (HTTP 401)` | Senha errada, usuário bloqueado por tentativas, Basic auth desabilitado ou conta só OAuth/SAML. | Confirmar a senha antes de repetir (bloqueio após 5 erros em 5 min); validar com o admin `[auth.basic] enabled` e o tipo da conta. |
| `Credencial sem acesso à organização (HTTP 403...)` | Usuário não é membro de nenhuma organização. | Adicionar o usuário às organizações a avaliar (papel Admin). |
| `resposta não-JSON (a URL aponta para o Grafana? ...)` | URL errada, ou SSO/proxy reverso devolvendo página HTML de login. | Usar a URL raiz do Grafana; pedir liberação do caminho `/api/` sem SSO no proxy. |
| `--orgs não encontrou organizações ...` | Nome não casa ou o usuário não é membro da org. | Conferir nomes com `--test`; usar curinga (`"NOC*"`) ou o ID. |
| `--formats inválido: ...` | Valor diferente de `pdf`, `pptx`, `none`. | Corrigir o parâmetro. |
| `... não gerado: módulo 'reportlab' ausente` (ou `pptx`) | Biblioteca opcional não instalada. | `pip install --user reportlab python-pptx` ou usar `--render-only` em outra máquina. |
| `caminho '...' bloqueado: assessment somente leitura` | Proteção read-only acionada (não deve ocorrer em uso normal). | Reportar ao mantenedor do script com o log completo. |
| Execução muito lenta / timeouts | Muitos dashboards, fontes lentas no health check. | `--timeout 120`, `--threads 2`, `--skip-ds-health`, `--max-dashboards`, ou limitar com `--orgs`. |
| Ruído/MTTR aparecem N/A | State history em Loki ou desabilitado, ou nenhum disparo na janela. | Confirmar `[unified_alerting.state_history]` com o cliente; é uma limitação, não um erro. |

Erros HTTP 429/5xx e falhas de rede transitórias são **repetidos automaticamente** (até 4 tentativas com espera de 1s, 2s e 4s). Erros de autenticação (401) **não** são repetidos.

---

## 10. Checklist do suporte

**Antes**
- [ ] Usuário `vertare` com **Grafana Admin = sim** e papel **Admin** em cada organização a avaliar.
- [ ] Janela de execução combinada com o cliente (o health check consulta cada fonte de dados uma vez).
- [ ] Python 3.8+ disponível na máquina de execução.
- [ ] `--test` executado sem endpoints essenciais `NEGADO`.

**Durante**
- [ ] Rodar com `--customer` e `--env-name` corretos (e `--expected-integrations zabbix` no Assaí).
- [ ] Acompanhar o log; anotar avisos de timeout/erro.

**Depois**
- [ ] Conferir no `relatorio.html` o apêndice de coleta (coletores `parcial`).
- [ ] Gerar PDF/PPTX (direto ou via `--render-only`).
- [ ] Copiar a pasta de saída por canal aprovado e **apagar do jump server**.
- [ ] Solicitar ao cliente que **remova o Grafana Admin** e desabilite o usuário de assessment (ou troque a senha).
- [ ] Limpar variáveis de ambiente da sessão (`unset GRAFANA_PASSWORD GRAFANA_USER` / `Remove-Item Env:GRAFANA_*`).

---

## 11. Referências rápidas de comandos

**Linux / jump server (bash):**
```bash
# ajuda completa dos parâmetros
python3 grafana_assessment.py --help

# variáveis (Assaí)
export GRAFANA_URL='https://grafana.corp.assai.com.br/'
export GRAFANA_USER='vertare'

# teste de conexão (pede a senha)
python3 grafana_assessment.py --test

# execução padrão
python3 grafana_assessment.py --customer "Assaí Atacadista" --env-name "Produção" --days 30 --expected-integrations zabbix

# jump server restrito (CA interna, sem proxy, sem PDF/PPTX)
python3 grafana_assessment.py --insecure --no-proxy --formats none --customer "Assaí Atacadista" --expected-integrations zabbix

# salvar o log da execução
python3 grafana_assessment.py --customer "Assaí Atacadista" 2>&1 | tee assessment.log

# regerar relatórios a partir da coleta
python3 grafana_assessment.py --render-only ./grafana-assessment-20261126-1600/dados.json --customer "Assaí Atacadista"

# empacotar o resultado e limpar a sessão
tar czf grafana-assessment-20261126-1600.tgz grafana-assessment-20261126-1600/
unset GRAFANA_PASSWORD GRAFANA_USER GRAFANA_URL GRAFANA_CA_BUNDLE
```

**Windows (PowerShell):** detalhes na [seção 5](#5-execução-no-windows-powershell).
```powershell
# ajuda completa dos parâmetros
py .\grafana_assessment.py --help

# variáveis (Assaí)
$env:GRAFANA_URL  = 'https://grafana.corp.assai.com.br/'
$env:GRAFANA_USER = 'vertare'

# teste de conexão (pede a senha)
py .\grafana_assessment.py --test

# execução padrão
py .\grafana_assessment.py --customer "Assaí Atacadista" --env-name "Produção" --days 30 --expected-integrations zabbix

# jump server restrito (CA interna, sem proxy, sem PDF/PPTX)
py .\grafana_assessment.py --insecure --no-proxy --formats none --customer "Assaí Atacadista" --expected-integrations zabbix

# salvar o log da execução (PowerShell 7+)
py .\grafana_assessment.py --customer "Assaí Atacadista" 2>&1 | Tee-Object -FilePath .\assessment.log

# regerar relatórios a partir da coleta
py .\grafana_assessment.py --render-only .\grafana-assessment-20261126-1600\dados.json --customer "Assaí Atacadista"

# empacotar o resultado e limpar a sessão
Compress-Archive -Path .\grafana-assessment-20261126-1600 -DestinationPath .\grafana-assessment-20261126-1600.zip
Remove-Item Env:GRAFANA_PASSWORD, Env:GRAFANA_USER, Env:GRAFANA_URL, Env:GRAFANA_CA_BUNDLE -ErrorAction SilentlyContinue
```

> Se `python3`/`py` não existir na máquina, use `python` no lugar (ex.: `python grafana_assessment.py --test`).
