// exposcan — procura ficheiros/caminhos sensíveis expostos (segredos,
// backups, metadados de VCS). O maior risco de falsos positivos aqui é um
// site que devolve 200 OK para QUALQUER caminho (SPA com catch-all, ou uma
// página de erro personalizada servida com status 200) — por isso primeiro
// mede-se uma "baseline": o corpo de um caminho quase de certeza inexistente,
// e qualquer resposta demasiado parecida com essa baseline é ignorada.
const crypto = require('crypto');
const { request, mapLimit } = require('../util/http');
const { finding } = require('../util/findings');

const TARGETS = [
  { path: '.env', severity: 'critical', label: 'Ficheiro .env (segredos/credenciais de ambiente)' },
  { path: '.git/config', severity: 'critical', label: 'Repositório .git exposto (config)' },
  { path: '.git/HEAD', severity: 'critical', label: 'Repositório .git exposto (HEAD)' },
  { path: '.git/index', severity: 'critical', label: 'Repositório .git exposto (index — histórico pode ser reconstruído)' },
  { path: '.aws/credentials', severity: 'critical', label: 'Credenciais AWS expostas' },
  { path: 'id_rsa', severity: 'critical', label: 'Chave privada SSH exposta (id_rsa)' },
  { path: 'wp-config.php.bak', severity: 'critical', label: 'Backup de configuração WordPress (credenciais de BD)' },
  { path: '.htpasswd', severity: 'high', label: 'Ficheiro .htpasswd exposto (hashes de password)' },
  { path: 'config.json', severity: 'medium', label: 'config.json exposto (pode conter segredos)' },
  { path: 'docker-compose.yml', severity: 'medium', label: 'docker-compose.yml exposto (pode revelar infraestrutura/segredos)' },
  { path: '.svn/entries', severity: 'high', label: 'Repositório .svn exposto' },
  { path: 'backup.zip', severity: 'high', label: 'Ficheiro backup.zip exposto' },
  { path: 'backup.sql', severity: 'critical', label: 'Dump de base de dados exposto (backup.sql)' },
  { path: 'database.sql', severity: 'critical', label: 'Dump de base de dados exposto (database.sql)' },
  { path: '.DS_Store', severity: 'low', label: '.DS_Store exposto (pode revelar nomes de ficheiros/estrutura)' },
  { path: 'phpinfo.php', severity: 'medium', label: 'phpinfo.php exposto (revela versão/configuração do servidor)' },
  { path: 'error_log', severity: 'medium', label: 'error_log exposto (pode revelar caminhos internos/stack traces)' },
  { path: '.well-known/security.txt', severity: 'info', label: 'security.txt encontrado (informativo — boa prática, não é um problema)' },
];

function hashBody(body) { return crypto.createHash('sha256').update(body.slice(0, 4000)).digest('hex'); }

async function check(baseUrl, { concurrency = 5 } = {}) {
  const findings = [];
  const base = baseUrl.replace(/\/+$/, '');

  // Baseline: um caminho aleatório que quase de certeza não existe.
  const probe = `${base}/__exposcan_${crypto.randomBytes(6).toString('hex')}_probe`;
  const baseline = await request(probe);
  const baselineHash = baseline.ok ? hashBody(baseline.body) : null;
  const baselineStatus = baseline.ok ? baseline.status : null;

  const results = await mapLimit(TARGETS, concurrency, async target => {
    const url = `${base}/${target.path}`;
    const res = await request(url);
    if (!res.ok || res.status !== 200) return null;
    // Resposta igual (ou quase) à baseline de 404/catch-all (ex: SPA com
    // fallback para index.html em qualquer caminho) — ignora sempre,
    // incluindo para security.txt, que também pode cair nesse catch-all.
    if (baselineHash && hashBody(res.body) === baselineHash) return null;
    if (baselineStatus && res.status === baselineStatus && res.body.length < 40) return null; // corpo vazio/trivial, pouco conclusivo
    return { target, url, res };
  });

  for (const hit of results) {
    if (!hit) continue;
    const { target, url, res } = hit;
    findings.push(finding({
      id: `exposed-${target.path.replace(/[^a-z0-9]+/gi, '-')}`,
      severity: target.severity,
      url,
      title: target.label,
      detail: `HTTP ${res.status} em ${url} — corpo com ${res.body.length} caracteres, distinto da resposta base do site para caminhos inexistentes.`,
      evidence: res.body.slice(0, 300),
      recommendation: target.path === '.well-known/security.txt'
        ? null
        : `Remover este ficheiro do diretório público, ou bloquear o acesso a nível do servidor web (ex: regra de ${target.path.startsWith('.git') ? 'negação a .git/' : 'negação a este caminho'}).`,
    }));
  }

  return findings;
}

module.exports = { check };
