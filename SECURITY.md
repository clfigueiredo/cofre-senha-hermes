# Política de segurança

## Modelo de proteção

- Senhas SSH são criptografadas com AES-256-GCM, nonce aleatório e UUID do equipamento como AAD.
- A chave AES fica separada do SQLite; ambos usam permissão `0600` e o diretório usa `0700`.
- A senha administrativa é armazenada apenas como hash `scrypt`.
- A interface e a listagem CLI nunca exibem senhas.
- O conector SSH recupera a senha somente em memória e exige uma chave de host previamente validada.

## Limites

Quem obtiver acesso ao sistema operacional com permissão para ler simultaneamente o banco e a chave poderá descriptografar as credenciais. Este projeto não substitui um HSM ou um gerenciador de segredos corporativo.

HTTP não deve ser exposto à Internet. O uso sem TLS deve ficar restrito a uma rede privada confiável e depende de autorização explícita do responsável.

## Arquivos que nunca devem ser publicados

- `equipment.db`, `equipment.db-wal`, `equipment.db-shm`
- `encryption.key`, `session.key`, `auth.json`, `known_hosts`
- `.env`, backups e logs com dados sensíveis

## Relato de vulnerabilidades

Não abra uma issue pública contendo detalhes exploráveis ou credenciais. Contate o mantenedor de forma privada pelo perfil do repositório e remova qualquer segredo antes de anexar evidências.

## Token exposto

Se um token ou senha for enviado em chat, issue, commit ou log, considere-o comprometido: revogue-o no provedor, gere outro com o menor escopo possível e limpe cópias locais.
