// exposcan — formatação do relatório para a consola (ANSI puro, sem
// dependências) e exportação para JSON.
const COLOR = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m', green: '\x1b[32m', magenta: '\x1b[35m', grey: '\x1b[90m',
};
const SEVERITY_STYLE = {
  critical: COLOR.red + COLOR.bold, high: COLOR.red, medium: COLOR.yellow, low: COLOR.cyan, info: COLOR.grey,
};
const SEVERITY_LABEL = { critical: 'CRÍTICO', high: 'ALTO', medium: 'MÉDIO', low: 'BAIXO', info: 'INFO' };

function riskLabel(score) {
  if (score >= 70) return { label: 'ELEVADO', color: COLOR.red + COLOR.bold };
  if (score >= 40) return { label: 'MODERADO', color: COLOR.yellow };
  if (score > 0) return { label: 'BAIXO', color: COLOR.cyan };
  return { label: 'SEM ACHADOS', color: COLOR.green };
}

function printConsole(result, { color = true } = {}) {
  const c = color ? COLOR : Object.fromEntries(Object.keys(COLOR).map(k => [k, '']));
  const line = '─'.repeat(60);

  console.log(`\n${c.bold}exposcan${c.reset} — relatório para ${c.cyan}${result.target}${c.reset}`);
  console.log(c.dim + line + c.reset);

  if (result.unreachable) {
    console.log(`${c.yellow}Alvo inacessível.${c.reset} ${result.findings[0].detail}`);
    return;
  }

  const risk = riskLabel(result.riskScore);
  console.log(`Risco agregado: ${color ? risk.color : ''}${result.riskScore}/100 (${risk.label})${c.reset}`);
  console.log(`${result.findings.length} achado(s) em ${(result.durationMs / 1000).toFixed(1)}s`);
  console.log(c.dim + line + c.reset);

  if (!result.findings.length) {
    console.log(`${c.green}Nenhum achado — nada óbvio detetado pelos checks disponíveis.${c.reset}`);
    console.log(`${c.dim}Isto não é uma garantia de segurança, só confirma a ausência dos problemas específicos que o exposcan procura.${c.reset}`);
    return;
  }

  for (const f of result.findings) {
    const style = color ? SEVERITY_STYLE[f.severity] : '';
    console.log(`\n${style}[${SEVERITY_LABEL[f.severity]}]${c.reset} ${c.bold}${f.title}${c.reset}`);
    if (f.url) console.log(`  ${c.dim}${f.url}${c.reset}`);
    console.log(`  ${f.detail}`);
    if (f.evidence) console.log(`  ${c.dim}Evidência: ${String(f.evidence).replace(/\n/g, ' ').slice(0, 200)}${c.reset}`);
    if (f.recommendation) console.log(`  ${c.green}→ ${f.recommendation}${c.reset}`);
  }
  console.log('');
}

function toJson(result) {
  return JSON.stringify(result, null, 2);
}

module.exports = { printConsole, toJson, riskLabel };
