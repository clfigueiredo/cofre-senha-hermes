# Cofre de Senhas Hermes

Inventário local de equipamentos para o Hermes Agent, com interface web, SQLite, senha SSH criptografada e conector que consome a credencial sem mostrá-la no chat ou na linha de comando.

## O que acompanha o repositório

- Cadastro de nome, IP, porta, usuário SSH, marca e senha.
- AES-256-GCM com chave separada do banco.
- Login administrativo com hash `scrypt`, CSRF, rate limit e cabeçalhos de segurança.
- Conector SSH com TOFU: registro automático no primeiro acesso e bloqueio de mudanças posteriores.
- Skill `equipment-registry-ops`, que orienta o Hermes a consultar o inventário (sem alterar o `SOUL.md`).
- Instalador idempotente para Linux e testes automatizados.

## Instalação pelo Hermes

Envie este repositório ao seu Hermes e peça:

> Instale este projeto seguindo o AGENTS.md, sem expor credenciais.

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
6. instala a skill no perfil Hermes ativo.

O instalador **não altera** o `SOUL.md` nem outros arquivos de personalidade do Hermes. Abra uma nova sessão do Hermes após instalar para carregar a skill.

## Primeiro acesso

Inicie a interface (por padrão escuta em todas as interfaces, porta 8787):

```bash
equipment-registry serve
```

Abra `http://<ip-do-servidor>:8787/setup` de qualquer máquina da rede local e crie a senha administrativa. Depois disso, cadastre os equipamentos pela própria interface. O `/setup` só aceita conexões de localhost ou de IPs privados e some após o primeiro administrador ser criado. Também é possível usar `equipment-registry init` no terminal. Nunca envie essa senha pelo chat.

## Backup consistente

Como o SQLite usa WAL, não copie apenas o arquivo do banco enquanto o serviço estiver ativo. Use o comando integrado, que usa a API de backup do SQLite e copia os arquivos de segurança com permissões privadas:

```bash
equipment-registry backup --output "$HOME/backups/cofre-$(date +%Y%m%d)"
```

O diretório de saída deve ser novo. Armazene-o em destino criptografado e protegido; ele contém banco e chave suficientes para recuperar as credenciais.

### Serviço persistente

Se o ambiente possuir `systemd --user`:

```bash
python3 scripts/install.py --service                 # escuta em 0.0.0.0:8787
python3 scripts/install.py --service --host 127.0.0.1  # só local
```

Verifique:

```bash
systemctl --user status cofre-senhas-hermes.service
curl --fail http://127.0.0.1:8787/health
```

## Rede e acesso

O padrão é `0.0.0.0:8787` (todas as interfaces). Para escutar só em um IP ou só localmente:

```bash
equipment-registry serve --host 192.168.1.10 --port 8787
equipment-registry serve --host 127.0.0.1
```

A interface usa HTTP sem TLS. Mantenha-a dentro da rede local ou VPN, restrinja a porta no firewall e nunca a publique diretamente na Internet. Atrás de um proxy HTTPS, defina `EQUIPMENT_REGISTRY_HTTPS=1` para marcar o cookie de sessão como `Secure`.

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

Por padrão, remove serviço, comando e skill (e o bloco de política de versões antigas no `SOUL.md`, se existir), mas preserva o cofre:

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
