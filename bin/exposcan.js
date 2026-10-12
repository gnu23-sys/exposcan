#!/usr/bin/env node
// exposcan — CLI. Mesmo princípio de segurança do resto do ecossistema
// DarkNode (ver pentest/tools.js): nunca corre sem confirmação explícita de
// que o utilizador tem autorização para testar o alvo, a menos que passe
// --yes para automação/CI (ex: scanear o teu próprio site num pipeline).
const readline = require('readline');
const fs = require('fs');
const { scan, normaliseTarget } = require('../src/scanner');
const { printConsole, toJson } = require('../src/report');

const HELP = `exposcan — scanner de misconfigurations e segredos expostos (cabeçalhos de segurança, .env/.git expostos, CORS, cookies, segredos em JS público).

Uso:
  exposcan <alvo> [opções]

Opções:
  --yes              Salta a confirmação interativa de autorização (uso em CI/scripts, sobre alvos próprios)
  --json <ficheiro>  Grava o relatório completo em JSON neste caminho
  --no-color         Desliga cores no output da consola
  --concurrency <n>  Pedidos em paralelo por check (default 5)
  --checks <lista>   Só corre estes checks, separados por vírgula (ex: headers,secrets)
                      Disponíveis: headers,cookies,serverInfo,cors,exposedFiles,directoryListing,secrets
  -h, --help         Mostra esta ajuda

Exemplos:
  exposcan exemplo.local
  exposcan https://exemplo.local --json relatorio.json
  exposcan exemplo.local --checks headers,secrets --yes

AVISO: usa isto só contra alvos que tens autorização explícita para testar.
Testar sistemas de terceiros sem autorização pode ser crime em muitas jurisdições.`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--yes') args.yes = true;
    else if (a === '--no-color') args.noColor = true;
    else if (a === '--json') args.json = argv[++i];
    else if (a === '--concurrency') args.concurrency = parseInt(argv[++i], 10);
    else if (a === '--checks') args.checks = argv[++i].split(',').map(s => s.trim()).filter(Boolean);
    else if (a === '-h' || a === '--help') args.help = true;
    else args._.push(a);
  }
  return args;
}

function confirm(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer.trim().toLowerCase()); }));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args._.length) { console.log(HELP); process.exit(args.help ? 0 : 1); }

  let baseUrl;
  try { baseUrl = normaliseTarget(args._[0]); }
  catch (e) { console.error(`Alvo inválido: ${e.message}`); process.exit(1); }

  if (!args.yes) {
    console.log(`\nVais scanear: ${baseUrl}`);
    console.log('Isto envia pedidos HTTP ao alvo (sondagem de ficheiros, headers, CORS, etc.) — só prossegue se tiveres autorização explícita para testar este alvo.');
    const answer = await confirm('Confirmas que tens autorização? (sim/não): ');
    if (answer !== 'sim' && answer !== 's' && answer !== 'yes' && answer !== 'y') {
      console.log('Cancelado.');
      process.exit(1);
    }
  }

  const spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let frame = 0;
  let lastLine = '';
  const tick = setInterval(() => {
    process.stdout.write(`\r${spinner[frame = (frame + 1) % spinner.length]} ${lastLine}`.padEnd(70));
  }, 80);

  try {
    const result = await scan(baseUrl, {
      concurrency: Number.isFinite(args.concurrency) ? args.concurrency : 5,
      checks: args.checks || null,
      onProgress: ({ phase }) => { lastLine = `a correr: ${phase}…`; },
    });
    clearInterval(tick);
    process.stdout.write('\r' + ' '.repeat(70) + '\r');

    printConsole(result, { color: !args.noColor });

    if (args.json) {
      fs.writeFileSync(args.json, toJson(result));
      console.log(`Relatório JSON gravado em ${args.json}`);
    }

    const hasCriticalOrHigh = result.findings.some(f => f.severity === 'critical' || f.severity === 'high');
    process.exit(hasCriticalOrHigh ? 2 : 0);
  } catch (e) {
    clearInterval(tick);
    process.stdout.write('\r' + ' '.repeat(70) + '\r');
    console.error(`Erro durante o scan: ${e.message}`);
    process.exit(1);
  }
}

main();
