// exposcan — CORS mal configurado. O caso realmente perigoso é o servidor
// REFLETIR a origem pedida (em vez de ter uma lista fechada) E aceitar
// credenciais — isso deixa qualquer site malicioso fazer pedidos autenticados
// (com cookies da vítima) e ler a resposta. Wildcard "*" sem credentials é
// normal/seguro para APIs públicas, por isso não é reportado como problema.
const { request } = require('../util/http');
const { finding } = require('../util/findings');

async function check(baseUrl) {
  const findings = [];
  const evilOrigin = 'https://exposcan-cors-test.invalid';
  const res = await request(baseUrl, { headers: { origin: evilOrigin } });
  if (!res.ok) return findings;

  const allowOrigin = res.headers.get('access-control-allow-origin');
  const allowCreds = (res.headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';

  if (allowOrigin === evilOrigin && allowCreds) {
    findings.push(finding({
      id: 'cors-reflected-origin-credentials', severity: 'critical', url: baseUrl,
      title: 'CORS reflete qualquer origem E aceita credenciais',
      detail: `O servidor devolveu "Access-Control-Allow-Origin: ${evilOrigin}" (uma origem inventada, nunca autorizada) junto com "Access-Control-Allow-Credentials: true" — qualquer site pode fazer pedidos autenticados (com cookies/sessão da vítima) a este endpoint e ler a resposta.`,
      evidence: `Origin pedido: ${evilOrigin}\nAccess-Control-Allow-Origin devolvido: ${allowOrigin}\nAccess-Control-Allow-Credentials: ${res.headers.get('access-control-allow-credentials')}`,
      recommendation: 'Nunca refletir o header Origin dinamicamente quando Allow-Credentials é true — usar uma lista fechada de origens confiáveis.',
    }));
  } else if (allowOrigin === evilOrigin) {
    findings.push(finding({
      id: 'cors-reflected-origin', severity: 'low', url: baseUrl,
      title: 'CORS reflete qualquer origem (sem credenciais)',
      detail: 'O servidor aceita qualquer origem em Access-Control-Allow-Origin. Sem Allow-Credentials isto é normalmente aceitável para uma API pública, mas vale confirmar que nenhum endpoint sensível depende de autenticação por cookie aqui.',
      evidence: `Origin pedido: ${evilOrigin}\nAccess-Control-Allow-Origin devolvido: ${allowOrigin}`,
      recommendation: 'Confirmar que esta API é mesmo pública e sem estado sensível por cookie; caso contrário, restringir a origens conhecidas.',
    }));
  }

  return findings;
}

module.exports = { check };
