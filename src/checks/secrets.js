// exposcan — segredos/chaves de API deixados no HTML ou em ficheiros JS
// públicos (erro clássico: meter uma chave "secreta" no código do frontend).
// Padrões com prefixos específicos o suficiente para não disparar em texto
// aleatório — cada serviço assina as suas chaves de forma reconhecível.
const { request, mapLimit } = require('../util/http');
const { finding } = require('../util/findings');

const PATTERNS = [
  { id: 'aws-access-key', severity: 'critical', label: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'aws-secret-key', severity: 'critical', label: 'Possível AWS Secret Access Key', re: /\baws(_|-)?secret(_|-)?(access(_|-)?)?key["']?\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/i },
  { id: 'google-api-key', severity: 'high', label: 'Google API Key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { id: 'stripe-live-key', severity: 'critical', label: 'Stripe Secret Key (LIVE)', re: /\bsk_live_[0-9a-zA-Z]{20,}\b/ },
  { id: 'stripe-restricted-key', severity: 'high', label: 'Stripe Restricted Key (LIVE)', re: /\brk_live_[0-9a-zA-Z]{20,}\b/ },
  { id: 'slack-token', severity: 'high', label: 'Slack Token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { id: 'github-token', severity: 'critical', label: 'GitHub Personal Access Token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { id: 'sendgrid-key', severity: 'high', label: 'SendGrid API Key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { id: 'twilio-key', severity: 'high', label: 'Twilio API Key', re: /\bSK[0-9a-fA-F]{32}\b/ },
  { id: 'private-key-block', severity: 'critical', label: 'Bloco de chave privada (PEM)', re: /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/ },
  { id: 'firebase-url', severity: 'low', label: 'URL de Firebase Realtime Database (confirmar regras de acesso)', re: /\bhttps?:\/\/[a-z0-9-]+\.firebaseio\.com\b/i },
  { id: 'generic-jwt', severity: 'low', label: 'Token JWT no código (confirmar se não é sensível/reutilizável)', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

function scanText(text, sourceUrl) {
  const hits = [];
  for (const p of PATTERNS) {
    const m = text.match(p.re);
    if (m) hits.push({ pattern: p, match: m[0], sourceUrl });
  }
  return hits;
}

// Extrai até MAX_SCRIPTS URLs de <script src="..."> do mesmo site (evita
// seguir para domínios de terceiros — CDNs, analytics — que não são o alvo).
const MAX_SCRIPTS = 15;
function extractSameOriginScripts(html, baseUrl) {
  const origin = new URL(baseUrl).origin;
  const urls = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) && urls.length < MAX_SCRIPTS) {
    try {
      const abs = new URL(m[1], baseUrl).href;
      if (new URL(abs).origin === origin) urls.push(abs);
    } catch { /* URL invalido no src - ignora */ }
  }
  return urls;
}

async function check(html, baseUrl, { concurrency = 5 } = {}) {
  const findings = [];
  const seen = new Set();

  const addHits = hits => {
    for (const hit of hits) {
      const key = hit.pattern.id + '|' + hit.match;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(finding({
        id: `secret-${hit.pattern.id}`,
        severity: hit.pattern.severity,
        url: hit.sourceUrl,
        title: `${hit.pattern.label} encontrada em código público`,
        detail: `Padrão correspondente a ${hit.pattern.label} detetado em ${hit.sourceUrl}.`,
        evidence: redact(hit.match),
        recommendation: 'Revogar/rodar esta credencial imediatamente (se for real) e nunca a incluir em código servido ao browser — mover para variáveis de ambiente no backend.',
      }));
    }
  };

  addHits(scanText(html, baseUrl));

  const scripts = extractSameOriginScripts(html, baseUrl);
  await mapLimit(scripts, concurrency, async scriptUrl => {
    const res = await request(scriptUrl);
    if (res.ok && res.body) addHits(scanText(res.body, scriptUrl));
  });

  return findings;
}

// Mostra só o suficiente para confirmar o achado sem publicar a chave toda
// num relatório que pode ser partilhado.
function redact(secret) {
  if (secret.length <= 12) return secret.slice(0, 4) + '…';
  return secret.slice(0, 8) + '…' + secret.slice(-4);
}

module.exports = { check };
