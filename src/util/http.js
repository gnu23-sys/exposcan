// exposcan — pequeno wrapper sobre fetch com timeout, user-agent próprio e
// limite de tamanho de resposta (evita gastar memória/tempo em respostas
// enormes quando só precisamos dos primeiros KB para analisar).
const USER_AGENT = 'exposcan/1.0 (+https://github.com/gnu23-sys/exposcan) security-research';
const DEFAULT_TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2MB — chega para HTML/JS normais, corta backups/dumps gigantes

async function request(url, { method = 'GET', headers = {}, timeoutMs = DEFAULT_TIMEOUT_MS, redirect = 'follow' } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      headers: { 'user-agent': USER_AGENT, ...headers },
      redirect,
      signal: controller.signal,
    });
    let body = '';
    let truncated = false;
    if (method !== 'HEAD') {
      const reader = res.body ? res.body.getReader() : null;
      if (reader) {
        const decoder = new TextDecoder();
        let bytes = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          bytes += value.length;
          if (bytes > MAX_BODY_BYTES) { truncated = true; try { await reader.cancel(); } catch { /* ja fechado */ } break; }
          body += decoder.decode(value, { stream: true });
        }
      }
    }
    return { ok: true, status: res.status, headers: res.headers, url: res.url, body, truncated };
  } catch (e) {
    return { ok: false, error: e.name === 'AbortError' ? 'timeout' : e.message };
  } finally {
    clearTimeout(timer);
  }
}

// Concorrência limitada — nunca martela o alvo com centenas de pedidos em
// simultâneo. `limit` pedidos de cada vez, o resto espera em fila.
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

module.exports = { request, mapLimit, sleep, USER_AGENT };
