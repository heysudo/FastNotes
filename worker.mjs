// FastNotes AI worker: turns an image prompt into an image URL by driving
// Claude Code headless with the Higgsfield MCP connector.
// One-time setup (see README): add the higgsfield MCP + complete its OAuth.
import http from 'node:http';
import { spawn } from 'node:child_process';

const PORT = 7777;
const CLAUDE_TIMEOUT_MS = 150000;

function runClaude(prompt) {
  const instruction = `You have access to the "higgsfield" MCP server. Task:
1. Call the higgsfield generate_image tool with params: model "nano_banana_pro", prompt exactly as given below, aspect_ratio "3:2", count 1. If that model is rejected, retry once with the catalog's recommended general image model.
2. Note the returned job id. Repeatedly call job_display with that id until status is "completed" (keep checking; do not give up before 90 seconds of attempts).
3. When completed, reply with ONLY the raw image URL (the full-resolution one) and nothing else. No markdown, no commentary.
If generation fails or authentication is missing, reply with exactly: ERROR: <one-line reason>

IMAGE PROMPT:
${prompt}`;

  return new Promise((resolve, reject) => {
    const child = spawn('claude', [
      '-p', instruction,
      '--output-format', 'json',
      '--model', 'claude-haiku-4-5',
      '--allowedTools', 'mcp__higgsfield__generate_image,mcp__higgsfield__job_display',
    ], { env: { ...process.env }, stdio: ['ignore', 'pipe', 'pipe'] });

    let out = '', err = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('claude timed out')); }, CLAUDE_TIMEOUT_MS);
    child.stdout.on('data', d => out += d);
    child.stderr.on('data', d => err += d);
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(`claude exit ${code}: ${err.slice(0, 400)}`));
      try {
        const j = JSON.parse(out);
        const text = (j.result || '').trim();
        if (text.startsWith('ERROR:')) return reject(new Error(text));
        const m = text.match(/https?:\/\/\S+\.(png|webp|jpe?g)(\?\S*)?/i);
        if (!m) return reject(new Error('no image URL in: ' + text.slice(0, 300)));
        resolve(m[0]);
      } catch (e) {
        reject(new Error('unparseable claude output: ' + out.slice(0, 300)));
      }
    });
  });
}

http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    res.writeHead(200); res.end('ok'); return;
  }
  if (req.method !== 'POST' || req.url !== '/generate') {
    res.writeHead(404); res.end(); return;
  }
  let body = '';
  req.on('data', d => { body += d; if (body.length > 64 * 1024) req.destroy(); });
  req.on('end', async () => {
    try {
      const { prompt } = JSON.parse(body);
      if (!prompt || prompt.length < 4) throw new Error('missing prompt');
      console.log(new Date().toISOString(), 'generate:', prompt.slice(0, 120));
      const url = await runClaude(prompt);
      console.log(new Date().toISOString(), 'done:', url);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ url }));
    } catch (e) {
      console.error(new Date().toISOString(), 'failed:', e.message);
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
  });
}).listen(PORT, () => console.log('fastnotes-ai worker on :' + PORT));
