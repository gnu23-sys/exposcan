# exposcan

Scanner de misconfigurations e segredos expostos, em Node.js puro — **zero dependências de runtime**.

Procura o tipo de erro que acontece sem ninguém reparar: um `.env` esquecido no diretório público, cabeçalhos de segurança em falta, CORS a refletir qualquer origem com credenciais, cookies sem `Secure`/`HttpOnly`, uma chave de API deixada num ficheiro JS do frontend.

```
$ exposcan exemplo.local

exposcan — relatório para https://exemplo.local
────────────────────────────────────────────────────────────
Risco agregado: 47/100 (MODERADO)
7 achado(s) em 1.7s
────────────────────────────────────────────────────────────

[CRÍTICO] Ficheiro .env (segredos/credenciais de ambiente)
  https://exemplo.local/.env
  HTTP 200 em .../.env — corpo com 312 caracteres, distinto da resposta base...
  → Remover este ficheiro do diretório público...

[MÉDIO] Sem Content-Security-Policy (CSP)
  ...
```

## Porquê

A maioria dos scanners de pentest envolve ferramentas já existentes (nmap, nuclei, sqlmap...). O `exposcan` não envolve nada — cada check é escrito do zero contra este projeto, focado numa categoria específica e bem definida: **exposição acidental**, não exploração ativa de vulnerabilidades de aplicação.

## Instalação

```bash
git clone https://github.com/gnu23-sys/exposcan.git
cd exposcan
npm link   # torna o comando "exposcan" global, opcional
```

Requer só Node.js ≥ 18 (usa `fetch` nativo). Sem dependências de terceiros.

## Uso

```bash
node bin/exposcan.js <alvo> [opções]
# ou, com npm link:
exposcan <alvo> [opções]
```

| Opção | Descrição |
|---|---|
| `--yes` | Salta a confirmação interativa de autorização (uso em CI/scripts, contra alvos próprios) |
| `--json <ficheiro>` | Grava o relatório completo em JSON |
| `--no-color` | Desliga cores no output |
| `--concurrency <n>` | Pedidos em paralelo por check (default 5) |
| `--checks <lista>` | Só corre estes checks, separados por vírgula |

Exemplos:

```bash
exposcan exemplo.local
exposcan https://exemplo.local --json relatorio.json
exposcan exemplo.local --checks headers,secrets --yes
```

O código de saída é `2` se houver pelo menos um achado crítico/alto (útil em pipelines de CI), `0` caso contrário.

## O que verifica

- **`headers`** — cabeçalhos de segurança HTTP em falta (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- **`exposedFiles`** — ficheiros/caminhos sensíveis publicamente acessíveis (`.env`, `.git/*`, `.aws/credentials`, backups de base de dados, `wp-config.php.bak`, etc.), com deteção de falsos positivos via comparação com a resposta base do site a um caminho inexistente (evita alarmes falsos em sites com catch-all/SPA).
- **`cookies`** — cookies sem `Secure`, `HttpOnly` ou `SameSite`.
- **`cors`** — CORS que reflete qualquer origem pedida *e* aceita credenciais (o caso realmente perigoso — permite a qualquer site ler respostas autenticadas da vítima).
- **`serverInfo`** — divulgação de versão em `Server`/`X-Powered-By`, e stack traces em páginas de erro.
- **`directoryListing`** — autoindex ativo em diretórios comuns (`/images/`, `/backup/`, `/uploads/`...).
- **`secrets`** — chaves de API/segredos deixados no HTML ou em ficheiros JS do mesmo domínio (AWS, Google, Stripe, Slack, GitHub, SendGrid, Twilio, blocos de chave privada PEM), com padrões específicos o suficiente para não disparar em texto aleatório.

## Aviso legal

Usa isto só contra alvos que tens autorização explícita para testar — o teu próprio site, ou um cliente com acordo escrito. Testar sistemas de terceiros sem autorização pode ser crime em muitas jurisdições (em Portugal, Lei do Cibercrime, Lei 109/2009). O CLI pede confirmação antes de cada scan, a menos que uses `--yes`.

Este projeto não faz exploração ativa (sem SQLi, sem brute-force, sem fuzzing) — só sondagem passiva/de baixo impacto para detetar exposições acidentais.

## Licença

MIT — ver [LICENSE](LICENSE).

---

Por [GNU23](https://github.com/gnu23-sys) — criador também da [DarkNode IA](https://github.com/gnu23-sys/Gnu23-).
