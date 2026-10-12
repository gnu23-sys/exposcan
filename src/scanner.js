// exposcan — orquestrador: busca a página principal uma vez e corre todos os
// checks (alguns reaproveitam essa resposta, outros fazem os seus próprios
// pedidos). Devolve sempre um relatório estruturado, mesmo que o alvo esteja
// em baixo (nesse caso, um único finding "info" a dizer isso).
const { request } = require('./util/http');
const { riskScore, sortBySeverity, finding } = require('./util/findings');
const headersCheck = require('./checks/headers');
const exposedFilesCheck = require('./checks/exposedFiles');
const cookiesCheck = require('./checks/cookies');
const corsCheck = require('./checks/cors');
const serverInfoCheck = require('./checks/serverInfo');
const directoryListingCheck = require('./checks/directoryListing');
const secretsCheck = require('./checks/secrets');

function normaliseTarget(input) {
  let url = input.trim();
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  const parsed = new URL(url); // lança se for inválido
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('o alvo tem de ser http:// ou https://');
  return parsed.origin + parsed.pathname.replace(/\/+$/, '');
}

async function scan(target, opts = {}) {
  const { concurrency = 5, checks: only = null, onProgress = () => {} } = opts;
  const baseUrl = normaliseTarget(target);
  const startedAt = Date.now();
  const enabled = name => !only || only.includes(name);

  onProgress({ phase: 'fetch', url: baseUrl });
  const mainRes = await request(baseUrl);
  if (!mainRes.ok) {
    return {
      target: baseUrl, startedAt, durationMs: Date.now() - startedAt, unreachable: true,
      findings: [finding({
        id: 'target-unreachable', severity: 'info', url: baseUrl,
        title: 'Alvo inacessível', detail: `Não foi possível ligar a ${baseUrl}: ${mainRes.error}`,
        recommendation: null,
      })],
      riskScore: 0,
    };
  }

  const findings = [];
  const jobs = [];

  if (enabled('headers')) jobs.push(Promise.resolve(headersCheck.check(mainRes, baseUrl)));
  if (enabled('cookies')) jobs.push(Promise.resolve(cookiesCheck.check(mainRes, baseUrl)));
  if (enabled('serverInfo')) { onProgress({ phase: 'serverInfo' }); jobs.push(serverInfoCheck.check(mainRes, baseUrl)); }
  if (enabled('cors')) { onProgress({ phase: 'cors' }); jobs.push(corsCheck.check(baseUrl)); }
  if (enabled('exposedFiles')) { onProgress({ phase: 'exposedFiles' }); jobs.push(exposedFilesCheck.check(baseUrl, { concurrency })); }
  if (enabled('directoryListing')) { onProgress({ phase: 'directoryListing' }); jobs.push(directoryListingCheck.check(baseUrl, { concurrency })); }
  if (enabled('secrets')) { onProgress({ phase: 'secrets' }); jobs.push(secretsCheck.check(mainRes.body, baseUrl, { concurrency })); }

  const results = await Promise.all(jobs);
  for (const r of results) findings.push(...r);

  return {
    target: baseUrl,
    startedAt,
    durationMs: Date.now() - startedAt,
    unreachable: false,
    findings: sortBySeverity(findings),
    riskScore: riskScore(findings),
  };
}

module.exports = { scan, normaliseTarget };
