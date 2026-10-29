# Política de segurança

## Modelo de proteção

- Senhas SSH são criptografadas com AES-256-GCM, nonce aleatório e UUID do equipamento como AAD.
- A chave AES fica separada do SQLite; ambos usam permissão `0600` e o diretório usa `0700`.
- A senha administrativa é armazenada apenas como hash `scrypt`.
- A interface e a listagem CLI nunca exibem senhas.
- O conector SSH recupera a senha somente em memória e usa TOFU: aceita e fixa a chave no primeiro acesso, bloqueando alterações posteriores.
- O conector SFTP reutiliza a mesma identidade SSH fixada e oferece somente listagem e download dentro de uma raiz explícita por equipamento.

No primeiro acesso, TOFU não protege contra interceptação ativa. Em ambientes de maior risco, use uma autoridade de certificados SSH ou outro mecanismo central de confiança.

## Limites

Quem obtiver acesso ao sistema operacional com permissão para ler simultaneamente o banco e a chave poderá descriptografar as credenciais. Este projeto não substitui um HSM ou um gerenciador de segredos corporativo.

## Inventário offline / console local

- Cadastros `offline` ficam em tabela adicional sem colunas de IP, porta, usuário,
  senha, relay ou SFTP. Esses campos são recusados na validação; não há criptografia
  de senha vazia nem endpoint fictício para satisfazer o esquema SSH legado.
- Cliente, host pai e tipo de console são metadados obrigatórios, limitados a 100
  caracteres sem controles; o estado da rede deve ser `disconnected`.
- O tipo é imutável na edição. A unicidade de nome/UUID entre SSH e offline é aplicada
  por triggers SQLite, inclusive para clientes antigos que escrevam na tabela SSH.
- CLI e conector bloqueiam offline antes de qualquer credencial, TOFU, relay ou rede;
  a camada de armazenamento também recusa recuperação de senha offline.
- Login, CSRF, escape HTML e CSP sem JavaScript continuam ativos. A escolha de tipo
  usa links e renderização no servidor, sem afrouxar a política de scripts.
- O estado de rede é declarativo, não uma garantia de isolamento. Nenhuma operação
  no hipervisor é efetuada e o host pai não se torna um alvo autorizado implicitamente.

## Relay SSH local

- Um equipamento pode usar opcionalmente um relay SSH somente em `127.0.0.1` ou `::1`.
- O relay altera apenas o transporte TCP; a identidade e a chave SSH fixada continuam sendo do equipamento cadastrado.
- Use relay apenas para túneis temporários ou serviços locais autorizados. Nunca cadastre IPs LAN, Internet ou DNS como relay.
- O relay não expõe portas: o túnel deve ficar vinculado ao loopback do host Hermes.

## SFTP somente leitura

- `sftp_root = NULL` mantém SFTP desabilitado; uma raiz POSIX absoluta delimita listagem e download.
- Caminhos enviados pelo operador devem ser relativos, sem `..`, controles ou separadores alternativos.
- O conector recusa symlinks nos componentes solicitados, valida contenção por componentes após `realpath`, limita entradas/tamanho/tempo e calcula SHA-256 durante o download.
- O arquivo local é criado exclusivamente, sem seguir symlink, e um parcial é removido em falha.
- Não existem operações SFTP de upload, exclusão, rename, criação de diretório ou alteração de atributos nesta versão.
- SFTP v3 não elimina completamente TOCTOU no filesystem remoto. A conta deve ser somente leitura e preferencialmente chrootada/restrita; um servidor hostil sempre controla os bytes e metadados entregues.

HTTP não deve ser exposto à Internet. O uso sem TLS deve ficar restrito a uma rede privada confiável e depende de autorização explícita do responsável.

## Arquivos que nunca devem ser publicados

- `equipment.db`, `equipment.db-wal`, `equipment.db-shm`
- `encryption.key`, `session.key`, `auth.json`, `known_hosts`
- `.env`, backups e logs com dados sensíveis

## Relato de vulnerabilidades

Não abra uma issue pública contendo detalhes exploráveis ou credenciais. Contate o mantenedor de forma privada pelo perfil do repositório e remova qualquer segredo antes de anexar evidências.

## Token exposto

Se um token ou senha for enviado em chat, issue, commit ou log, considere-o comprometido: revogue-o no provedor, gere outro com o menor escopo possível e limpe cópias locais.
