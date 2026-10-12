// exposcan — cabeçalhos de segurança HTTP em falta ou mal configurados.
// Inspirado no Mozilla Observatory / securityheaders.com, mas focado nos
// cabeçalhos com maior impacto prático em vez de cobrir tudo.
const { finding } = require('../util/findings');

function check(res, baseUrl) {
  const findings = [];
  const h = res.headers;
  const get = name => h.get(name);

  if (!get('strict-transport-security') && baseUrl.startsWith('https:')) {
    findings.push(finding({
      id: 'missing-hsts', severity: 'medium', url: baseUrl,
      title: 'Sem Strict-Transport-Security (HSTS)',
      detail: 'O site serve HTTPS mas não força o browser a usar sempre HTTPS — um downgrade para HTTP (ex: rede comprometida) não é bloqueado automaticamente.',
      recommendation: 'Adicionar "Strict-Transport-Security: max-age=31536000; includeSubDomains" às respostas.',
    }));
  }

  if (!get('content-security-policy')) {
    findings.push(finding({
      id: 'missing-csp', severity: 'medium', url: baseUrl,
      title: 'Sem Content-Security-Policy (CSP)',
      detail: 'Sem CSP, um XSS bem-sucedido tem muito mais liberdade (scripts inline, origens externas arbitrárias, etc.) do que teria com uma política restritiva.',
      recommendation: 'Definir uma CSP mínima (ex: default-src \'self\') e apertar progressivamente.',
    }));
  }

  const xfo = get('x-frame-options');
  const csp = get('content-security-policy') || '';
  if (!xfo && !/frame-ancestors/i.test(csp)) {
    findings.push(finding({
      id: 'missing-frame-protection', severity: 'low', url: baseUrl,
      title: 'Sem proteção contra clickjacking (X-Frame-Options / frame-ancestors)',
      detail: 'A página pode ser carregada dentro de um <iframe> de outro site, possibilitando ataques de clickjacking/UI redressing.',
      recommendation: 'Adicionar "X-Frame-Options: DENY" (ou SAMEORIGIN) ou "Content-Security-Policy: frame-ancestors \'none\'".',
    }));
  }

  if (!get('x-content-type-options')) {
    findings.push(finding({
      id: 'missing-content-type-options', severity: 'low', url: baseUrl,
      title: 'Sem X-Content-Type-Options',
      detail: 'Sem "nosniff", browsers mais antigos podem tentar adivinhar o tipo de um ficheiro e executá-lo de forma inesperada (ex: um upload de imagem interpretado como HTML/JS).',
      recommendation: 'Adicionar "X-Content-Type-Options: nosniff".',
    }));
  }

  if (!get('referrer-policy')) {
    findings.push(finding({
      id: 'missing-referrer-policy', severity: 'info', url: baseUrl,
      title: 'Sem Referrer-Policy',
      detail: 'Sem esta política, o browser pode enviar o URL completo da página (incluindo query strings, que às vezes têm tokens/dados) como Referer para sites externos.',
      recommendation: 'Adicionar "Referrer-Policy: strict-origin-when-cross-origin" (ou mais restritivo).',
    }));
  }

  if (!get('permissions-policy')) {
    findings.push(finding({
      id: 'missing-permissions-policy', severity: 'info', url: baseUrl,
      title: 'Sem Permissions-Policy',
      detail: 'Sem esta política, não há controlo explícito sobre que APIs do browser (câmara, microfone, geolocalização...) podem ser usadas na página, incluindo por scripts de terceiros.',
      recommendation: 'Adicionar "Permissions-Policy" a restringir o que não é necessário (ex: "geolocation=(), camera=(), microphone=()").',
    }));
  }

  return findings;
}

module.exports = { check };
