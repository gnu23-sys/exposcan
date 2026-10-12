// exposcan — divulgação de informação: versões em cabeçalhos e stack traces
// em páginas de erro. Nada aqui é "explorável" por si só, mas facilita muito
// a vida de quem está a atacar (sabe exatamente que versão/framework visar).
const { request } = require('../util/http');
const { finding } = require('../util/findings');

const STACK_TRACE_PATTERNS = [
  /at [\w$.]+\s+\(.*:\d+:\d+\)/,            // stack trace Node/JS
  /Traceback \(most recent call last\)/,     // Python
  /Fatal error:.*on line \d+/i,              // PHP
  /Microsoft OLE DB Provider for/i,          // ASP clássico
  /System\.\w+Exception/,                    // .NET
  /org\.\w+\.\w+Exception/,                  // Java
];

async function check(res, baseUrl) {
  const findings = [];
  const server = res.headers.get('server');
  const poweredBy = res.headers.get('x-powered-by');

  // "nginx" ou "Apache" sem versão é normal/não é achado; só interessa quando
  // revela um NÚMERO DE VERSÃO específico (ex: "Apache/2.4.7 (Ubuntu)").
  if (server && /\d+\.\d+/.test(server)) {
    findings.push(finding({
      id: 'server-version-disclosure', severity: 'info', url: baseUrl,
      title: 'Cabeçalho Server revela versão do software',
      detail: `Header Server: "${server}" — facilita identificar CVEs conhecidos para esta versão exata.`,
      evidence: server,
      recommendation: 'Configurar o servidor para omitir a versão no header Server (ex: ServerTokens Prod no Apache, server_tokens off no nginx).',
    }));
  }
  if (poweredBy) {
    findings.push(finding({
      id: 'x-powered-by-disclosure', severity: 'info', url: baseUrl,
      title: 'Cabeçalho X-Powered-By revela a tecnologia usada',
      detail: `Header X-Powered-By: "${poweredBy}".`,
      evidence: poweredBy,
      recommendation: 'Remover o header X-Powered-By (ex: "app.disable(\'x-powered-by\')" no Express).',
    }));
  }

  // Força um 404/erro com um caminho estranho e verifica se a página de erro
  // vaza um stack trace em vez de uma mensagem genérica.
  const errRes = await request(`${baseUrl.replace(/\/+$/, '')}/__exposcan_force_error_<script>`);
  if (errRes.ok && errRes.body) {
    const matched = STACK_TRACE_PATTERNS.find(re => re.test(errRes.body));
    if (matched) {
      findings.push(finding({
        id: 'stack-trace-disclosure', severity: 'medium', url: baseUrl,
        title: 'Página de erro revela stack trace',
        detail: 'Uma página de erro expõe detalhes internos (caminhos de ficheiros, linhas de código, framework) em vez de uma mensagem genérica.',
        evidence: errRes.body.slice(0, 400),
        recommendation: 'Desligar o modo de debug/stack traces detalhados em produção; mostrar sempre uma página de erro genérica ao utilizador.',
      }));
    }
  }

  return findings;
}

module.exports = { check };
