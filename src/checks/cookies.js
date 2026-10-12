// exposcan — flags de segurança em cookies (Secure, HttpOnly, SameSite).
// Node/fetch expõem só o PRIMEIRO Set-Cookie via headers.get() — por isso
// usa-se getSetCookie() (disponível no undici/Node 18.14+) quando existir,
// com fallback para a leitura simples em runtimes mais antigos.
const { finding } = require('../util/findings');

function parseSetCookie(raw) {
  const parts = raw.split(';').map(p => p.trim());
  const [nameValue, ...attrs] = parts;
  const name = (nameValue || '').split('=')[0];
  const lower = attrs.map(a => a.toLowerCase());
  return {
    name: name || '(sem nome)',
    secure: lower.some(a => a === 'secure'),
    httpOnly: lower.some(a => a === 'httponly'),
    sameSite: (attrs.find(a => a.toLowerCase().startsWith('samesite=')) || '').split('=')[1] || null,
  };
}

function check(res, baseUrl) {
  const findings = [];
  const raws = typeof res.headers.getSetCookie === 'function'
    ? res.headers.getSetCookie()
    : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);

  for (const raw of raws) {
    const c = parseSetCookie(raw);
    const problems = [];
    if (baseUrl.startsWith('https:') && !c.secure) problems.push('sem flag Secure (pode ser enviado por HTTP)');
    if (!c.httpOnly) problems.push('sem flag HttpOnly (legível por JavaScript — risco acrescido se houver XSS)');
    if (!c.sameSite || c.sameSite.toLowerCase() === 'none') problems.push(`SameSite ${c.sameSite ? '"None"' : 'em falta'} (mais exposto a CSRF)`);
    if (!problems.length) continue;

    findings.push(finding({
      id: `cookie-flags-${c.name}`,
      severity: problems.length >= 2 ? 'medium' : 'low',
      url: baseUrl,
      title: `Cookie "${c.name}" sem todas as flags de segurança`,
      detail: problems.join('; ') + '.',
      evidence: raw.slice(0, 200),
      recommendation: 'Definir Secure, HttpOnly (exceto se o JS do site precisar mesmo de ler o cookie) e SameSite=Lax ou Strict.',
    }));
  }

  return findings;
}

module.exports = { check };
