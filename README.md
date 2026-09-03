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

## Licença

MIT. Consulte `LICENSE` e `SECURITY.md`.
