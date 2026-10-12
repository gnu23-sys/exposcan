// exposcan — estrutura comum de um "finding" (achado) e pontuação de risco
// agregada 0-100, mesmo padrão já usado no email_osint.py do projeto DarkNode
// (pontuação só-leitura, informativa — nunca um veredito automático).
const SEVERITY_WEIGHT = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function finding({ id, severity, title, detail, evidence, recommendation, url }) {
  if (!SEVERITY_WEIGHT.hasOwnProperty(severity)) throw new Error(`severidade desconhecida: ${severity}`);
  return { id, severity, title, detail, evidence: evidence || null, recommendation, url: url || null };
}

// Soma dos pesos, capada a 100 e com diminishing returns leve (raiz quadrada
// da soma) — um alvo com 10 findings "low" não deve dar o mesmo que 2
// "critical", mas também não deve somar linearmente até explodir o limite.
function riskScore(findings) {
  const raw = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  if (raw <= 0) return 0;
  return Math.min(100, Math.round(Math.sqrt(raw) * 10));
}

function sortBySeverity(findings) {
  return [...findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
}

module.exports = { finding, riskScore, sortBySeverity, SEVERITY_RANK };
