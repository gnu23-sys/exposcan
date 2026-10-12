// exposcan — directory listing ativo (autoindex do Apache/nginx) em
// diretórios comuns, que pode revelar ficheiros que ninguém sabia estarem
// publicamente acessíveis.
const { request, mapLimit } = require('../util/http');
const { finding } = require('../util/findings');

const DIRS = ['images', 'uploads', 'backup', 'backups', 'files', 'assets', 'static', 'tmp', 'old', 'logs'];

const LISTING_PATTERNS = [
  /<title>Index of \//i,
  /\[To Parent Directory\]/i,
  /Directory listing for \//i,
];

async function check(baseUrl, { concurrency = 5 } = {}) {
  const findings = [];
  const base = baseUrl.replace(/\/+$/, '');

  const results = await mapLimit(DIRS, concurrency, async dir => {
    const url = `${base}/${dir}/`;
    const res = await request(url);
    if (!res.ok || res.status !== 200 || !res.body) return null;
    const matched = LISTING_PATTERNS.some(re => re.test(res.body));
    return matched ? { url, res } : null;
  });

  for (const hit of results) {
    if (!hit) continue;
    findings.push(finding({
      id: `directory-listing-${hit.url}`, severity: 'medium', url: hit.url,
      title: 'Directory listing ativo',
      detail: `${hit.url} devolve uma listagem de ficheiros do servidor em vez de um 403/404.`,
      evidence: hit.res.body.slice(0, 300),
      recommendation: 'Desativar o autoindex neste diretório (ex: "Options -Indexes" no Apache, remover "autoindex on" no nginx).',
    }));
  }

  return findings;
}

module.exports = { check };
