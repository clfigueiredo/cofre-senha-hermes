# Cofre de Senhas Hermes

Inventário local de equipamentos para o Hermes Agent, com interface web, SQLite, senha SSH criptografada e conector que consome a credencial sem mostrá-la no chat ou na linha de comando.

## O que acompanha o repositório

- Cadastro de nome, IP, porta, usuário SSH, marca e senha.
- AES-256-GCM com chave separada do banco.
- Login administrativo com hash `scrypt`, CSRF, rate limit e cabeçalhos de segurança.
- Conector SSH com TOFU: registro automático no primeiro acesso e bloqueio de mudanças posteriores.
- Skill `equipment-registry-ops` e política obrigatória para o `SOUL.md`.
- Instalador idempotente para Linux e testes automatizados.

## Instalação pelo Hermes

Envie este repositório ao seu Hermes e peça:

> Instale este projeto seguindo o AGENTS.md, sem expor credenciais. Mantenha a interface em localhost, salvo se eu autorizar explicitamente acesso pela rede privada.

O Hermes deverá revisar os arquivos e executar:

```bash
python3 scripts/install.py
```

O instalador:

1. valida a presença do `uv`;
2. instala dependências reproduzíveis pelo `uv.lock`;
3. executa os testes;
4. instala o comando `equipment-registry`;
5. inicializa o armazenamento privado;
6. instala a skill no perfil Hermes ativo;
7. adiciona ao `SOUL.md` a política obrigatória, preservando backup quando houver mudança.

Abra uma nova sessão do Hermes após instalar para carregar a skill e a política.

## Primeiro acesso

Inicie apenas em localhost:

```bash
equipment-registry serve --host 127.0.0.1 --port 8787
```

Abra `http://127.0.0.1:8787/setup` e crie a senha administrativa, ou execute `equipment-registry init` para defini-la de modo interativo. Nunca envie essa senha pelo chat. Uma nova execução de `init` é recusada; `--force` redefine deliberadamente o administrador existente.

## Backup consistente

Como o SQLite usa WAL, não copie apenas o arquivo do banco enquanto o serviço estiver ativo. Use o comando integrado, que usa a API de backup do SQLite e copia os arquivos de segurança com permissões privadas:

```bash
equipment-registry backup --output "$HOME/backups/cofre-$(date +%Y%m%d)"
```

O diretório de saída deve ser novo. Armazene-o em destino criptografado e protegido; ele contém banco e chave suficientes para recuperar as credenciais.

### Serviço persistente

Se o ambiente possuir `systemd --user`:

```bash
python3 scripts/install.py --service
```

Verifique:

```bash
systemctl --user status cofre-senhas-hermes.service
curl --fail http://127.0.0.1:8787/health
```

## Rede privada

O padrão seguro é `127.0.0.1`. Para uma LAN privada, inicialize primeiro o administrador, confirme o IP privado correto e restrinja a porta no firewall. Depois, com autorização explícita:

```bash
python3 scripts/install.py --service --host 192.168.1.10 --port 8787 --insecure-private-lan
```

Sem serviço:

```bash
EQUIPMENT_REGISTRY_ALLOW_REMOTE=1 \
EQUIPMENT_REGISTRY_ALLOW_INSECURE_HTTP=I_ACCEPT_PRIVATE_LAN_RISK \
equipment-registry serve --host 192.168.1.10 --port 8787
```

HTTP sem TLS só deve ser usado quando o responsável aceitar o risco numa rede privada confiável. Nunca publique a porta diretamente na Internet.

## Uso seguro pelo Hermes

Listar metadados, sem senha:

```bash
equipment-registry list
```

Executar uma consulta pelo conector interno. No primeiro uso, a chave SSH apresentada é registrada automaticamente; nos acessos seguintes, qualquer mudança é recusada:

```bash
equipment-registry run 'SW-CORE-01' --command 'show version'
```

A senha é descriptografada somente dentro do processo do conector. O comando remoto e sua saída ainda podem ser sensíveis; o Hermes deve carregar a skill da plataforma, limitar o escopo e redigir segredos antes de responder.

Para equipamentos com uma raiz SFTP explícita configurada, listar apenas metadados:

```bash
equipment-registry sftp-list 'Supply-FTP' --path ''
```

Baixar um arquivo para um caminho local novo, sem sobrescrita, retornando tamanho e SHA-256:

```bash
equipment-registry sftp-download 'Supply-FTP' 'supply.war' --output '/caminho/novo/supply.war'
```

O destino é criado com permissão `0600`, `O_EXCL` e `O_NOFOLLOW`; arquivos existentes e symlinks são recusados, e um parcial é removido se a transferência falhar. A primeira versão SFTP oferece somente listagem e download: não há upload, remoção, rename, `mkdir`, `chmod` ou execução remota.

## Console local / offline

Na interface autenticada, selecione **+ Console local / offline** (também disponível
no formulário de novo equipamento). Preencha nome, marca, cliente, host pai e tipo
de console. O único estado de rede permitido é **Rede desconectada**.

Exemplo de preenchimento, **não um cadastro automático**: nome `n8n-restore-offline`,
cliente `GOITS`, host pai `DESKTOP-5ERNE8J`, tipo de console `hyper-v`; informe a marca
adequada no formulário. Não informe IP, porta, usuário ou senha. Relay e SFTP também
não se aplicam. O backend recusa esses campos se enviados em um POST manipulado.

- O registro apenas documenta a VM. Não verifica/desconecta a rede, não abre um console,
  não liga a VM e não autoriza conexão ao host pai. Mantenha a VM isolada no hipervisor.
- `equipment-registry list` inclui `access_type` (`ssh` ou `offline`). Para offline,
  `ip`, `ssh_port` e `username` são `null`; os campos `client`, `parent_host`,
  `console_type` e `network_state` descrevem o cadastro, sem credenciais.
- `run`, `sftp-list` e `sftp-download` recusam offline **antes de obter/descriptografar
  senha, criar destino de download, consultar TOFU ou tentar conexão**.
- O tipo de acesso não pode ser convertido durante a edição. Um novo tipo exige
  cadastro distinto e autorização própria; não existe promoção implícita para SSH.
- Monitoramento continua separado em `monitor-list`. Offline não concede permissão
  para sondas de rede e não aparece nessa listagem.

### Migração e ativação de uma atualização local

A inicialização cria a tabela adicional `offline_equipment` e triggers de unicidade
entre SSH e offline, sem reescrever a tabela SSH, seus ciphertexts ou os alvos de
monitoramento. A tabela offline não tem colunas de endpoint ou credencial. A migração
é idempotente; não exclua tabelas para voltar a uma versão anterior (versões antigas
não exibem os registros offline).

Antes da ativação, o operador deve providenciar o backup consistente descrito acima.
Se a aplicação roda a partir do código-fonte/instalação editável, precisa reiniciar o
processo web para carregar o novo backend. **O instalador padrão usa uma cópia do
pacote (`uv tool install`), não uma instalação editável**: nesse caso, atualize também
o pacote, em janela autorizada, antes de reiniciar. Não basta recarregar o navegador.

Conforme `scripts/install.py`, o serviço padrão é `cofre-senhas-hermes.service` em
`~/.config/systemd/user/cofre-senhas-hermes.service`, executando
`~/.local/bin/equipment-registry`. Isso documenta o instalador, não confirma o serviço
real da máquina. Para essa instalação padrão, os comandos de ativação são:

```bash
# Somente após autorização operacional, backup e confirmação da instalação alvo:
uv tool install --force .
systemctl --user restart cofre-senhas-hermes.service
```

Não é necessário executar `scripts/install.py` para esta atualização; ele também
altera skill/política. Nenhum restart, instalação global, mudança de política ou
cadastro em banco real faz parte dos testes locais.

## Dados persistentes

Por padrão, ficam em `~/.local/share/equipment-registry/`:

- `equipment.db` — SQLite com ciphertext.
- `encryption.key` — chave AES-256.
- `session.key` — assinatura das sessões.
- `auth.json` — hash administrativo.
- `known_hosts` — chaves SSH fixadas automaticamente no primeiro acesso.

O diretório usa `0700`; os arquivos sensíveis usam `0600`. Faça backup criptografado de `equipment.db` e `encryption.key` em conjunto. Nunca publique esses arquivos.

Para outro diretório:

```bash
export EQUIPMENT_REGISTRY_DATA_DIR=/caminho/privado
```

## Desenvolvimento e verificação

```bash
uv sync --frozen --extra dev
uv run pytest -q
uv run ruff check .
uv run bandit -q -r src scripts
uv run pip-audit
```

O teste opcional de navegador `tests/browser_offline.py` requer Playwright/Chromium
(instalados separadamente do ambiente de produção). Ele inicia um servidor apenas em
loopback com porta efêmera, cria dados temporários pela interface e valida cadastro,
edição/exclusão e layout em 375, 768 e 1440 px. `QA_CHROMIUM` permite indicar um binário
já instalado. O 404 do favicon preexistente é isolado no harness, não na aplicação.

```bash
python tests/browser_offline.py
```

## Desinstalação

Por padrão, remove serviço, comando, skill e política, mas preserva o cofre:

```bash
python3 scripts/uninstall.py
```

A purga é destrutiva e exige confirmação literal:

```bash
python3 scripts/uninstall.py --purge-data --confirm 'PURGE EQUIPMENT REGISTRY'
```

Remover `encryption.key` torna irrecuperável qualquer cópia isolada do banco.

## Limitações

A criptografia em repouso não protege contra alguém que obtenha simultaneamente o banco e a chave. O projeto é voltado a inventários locais e laboratórios; ambientes de alta criticidade devem considerar um gerenciador de segredos dedicado, segregação de privilégios, HTTPS/VPN e auditoria centralizada.

SFTP v3 não oferece uma defesa portátil equivalente a `openat(..., O_NOFOLLOW)` no servidor. O conector valida raiz, componentes, `realpath`, tipo antes/depois de abrir, tamanho e bytes recebidos, mas uma conta remota hostil ainda controla os dados e pode explorar janelas TOCTOU. Use uma conta SFTP somente leitura e preferencialmente chrootada/restrita.

## Licença

MIT. Consulte `LICENSE` e `SECURITY.md`.
