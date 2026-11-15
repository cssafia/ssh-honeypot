/* Slides 01-06: title, scenario, questions, honeypot, Cowrie, vocabulary */
(function () {
  'use strict';
  const pick = (a) => a[(Math.random() * a.length) | 0];
  const rnd = (a, b) => a + Math.random() * (b - a);
  const SVGNS = 'http://www.w3.org/2000/svg';
  const CREDS = ['root:123456', 'admin:admin', 'pi:raspberry', 'ubuntu:ubuntu', 'root:toor', 'test:test',
    'oracle:oracle', 'user:password', 'root:qwerty', 'admin:1234', 'postgres:postgres', 'root:letmein',
    'ubnt:ubnt', 'guest:guest', 'root:admin', 'support:support', 'root:welcome', 'root:12345678'];

  /* ===================================================================== 01 title */
  (function () {
    const T = Deck.timers();
    let stopRain = null, run = 0;
    const sleep = (ms) => new Promise((r) => T.after(r, ms));

    function startRain() {
      const cv = $('#rain'), ctx = cv.getContext('2d');
      const cols = 11, w = 1280 / cols;
      const mk = (i) => ({ x: i * w + 6, y: rnd(-100, 720), v: rnd(34, 80), s: pick(CREDS), a: rnd(.35, .95) });
      const drops = Array.from({ length: cols }, (_, i) => mk(i));
      ctx.fillStyle = '#0b0d0c'; ctx.fillRect(0, 0, 1280, 720);
      ctx.font = '15px "DejaVu Sans Mono", Consolas, monospace';
      return Deck.loop((t, dt) => {
        if (dt > 100) dt = 16;
        ctx.fillStyle = 'rgba(11,13,12,.14)'; ctx.fillRect(0, 0, 1280, 720);
        drops.forEach((d, i) => {
          d.y += d.v * dt / 1000;
          if (d.y > 740) Object.assign(d, mk(i), { y: -20 });
          ctx.fillStyle = 'rgba(57,255,20,' + d.a + ')';
          ctx.fillText(d.s, d.x, d.y);
        });
      });
    }

    async function typeInto(div, text, speed, token) {
      for (let i = 1; i <= text.length; i++) {
        if (token !== run) return false;
        div.textContent = text.slice(0, i);
        await sleep(speed);
      }
      return true;
    }
    async function terminal(token) {
      const body = $('#mt-body'), cnt = $('#mt-count');
      const ATT = [['root', '123456', 0], ['admin', 'admin', 0], ['pi', 'raspberry', 0], ['ubuntu', 'ubuntu', 0], ['root', 'toor', 0], ['root', 'Passw0rd#1', 1]];
      while (token === run) {
        body.innerHTML = '';
        let n = 0;
        for (const [u, p, ok] of ATT) {
          n += 1; cnt.textContent = 'attempt #' + (n + 340);
          const l1 = document.createElement('div'); l1.className = 'cur'; body.appendChild(l1);
          if (!(await typeInto(l1, 'login: ' + u + '  password: ' + p, 24, token))) return;
          l1.classList.remove('cur');
          await sleep(220);
          if (token !== run) return;
          const l2 = document.createElement('div');
          l2.className = ok ? 'good' : 'bad';
          l2.textContent = ok ? '  ✓ access granted — welcome to the FAKE shell' : '  ✗ permission denied';
          body.appendChild(l2);
          while (body.children.length > 4) body.removeChild(body.firstChild);
          await sleep(ok ? 2600 : 380);
        }
      }
    }

    const jar = $('#jar'), art = $('#tart');
    jar.addEventListener('click', () => {
      art.classList.add('caught');
      T.after(() => art.classList.remove('caught'), 3200);
    });

    Deck.register('title', {
      enter() {
        run += 1;
        stopRain = startRain();
        terminal(run);
      },
      leave() {
        run += 1;
        if (stopRain) stopRain();
        T.clear();
        art.classList.remove('caught');
      },
    });
  })();

  /* ================================================================= 02 scenario */
  (function () {
    const flow = $('#sc-flow'), cntEl = $('#sc-count'), nEl = $('#sc-n');
    const srv = $$('#scene .srvs use');
    srv.forEach((u, i) => { u.style.transitionDelay = (i * 90) + 'ms'; });
    let stop = null, packets = [], acc = 0, attempts = 300;

    function setCount() { cntEl.textContent = 'attempts: ' + attempts; nEl.textContent = attempts; }
    function startFlow() {
      if (stop) return;
      stop = Deck.loop((t, dt) => {
        if (dt > 100) dt = 16;
        acc += dt;
        if (acc > 360) {
          acc = 0;
          const el = document.createElementNS(SVGNS, 'text');
          el.setAttribute('class', 'pk');
          el.textContent = pick(CREDS);
          flow.appendChild(el);
          packets.push({ el, x: 150, y: 345 + rnd(-30, 30), life: 0 });
        }
        packets = packets.filter((p) => {
          p.x += 150 * dt / 1000; p.life += dt;
          p.el.setAttribute('x', p.x.toFixed(1)); p.el.setAttribute('y', p.y.toFixed(1));
          p.el.setAttribute('opacity', Math.min(1, (322 - p.x) / 60, p.life / 200).toFixed(2));
          if (p.x >= 322) { p.el.remove(); attempts += 1; setCount(); return false; }
          return true;
        });
      });
    }
    function stopFlow() {
      if (stop) stop();
      stop = null;
      packets.forEach((p) => p.el.remove());
      packets = [];
    }
    Deck.register('scenario', {
      enter() { attempts = 300; setCount(); },
      leave() { stopFlow(); },
      step(n) { if (n >= 2 && n <= 4) startFlow(); else stopFlow(); if (n < 2) { attempts = 300; setCount(); } },
    });
  })();

  /* ================================================================ 03 questions */
  (function () {
    $$('#questions .qcard').forEach((c) => {
      const flip = () => c.classList.toggle('flipped');
      c.addEventListener('click', flip);
      c.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); flip(); }
      });
    });
    Deck.register('questions', { enter() { $$('#questions .qcard').forEach((c) => c.classList.remove('flipped')); } });
  })();

  /* ================================================================ 04 honeypot */
  (function () {
    const T = Deck.timers();
    const scene = $('#hp-scene'), btn = $('#hp-btn'), log = $('#hp-log');
    const clock = () => new Date().toLocaleTimeString('en-GB');
    function line(cls, text) {
      const d = document.createElement('div'); d.innerHTML = '<span class="' + cls + '">' + text + '</span>'; log.appendChild(d);
      while (log.children.length > 3) log.removeChild(log.firstChild);
    }
    function reset() {
      T.clear(); scene.classList.remove('caught'); log.innerHTML = ''; btn.textContent = '▶ Touch the bait';
    }
    function run() {
      reset();
      T.after(() => {
        scene.classList.add('caught'); btn.textContent = '↺ Reset';
        line('l', '[' + clock() + '] camera: someone approaches the bait…');
      }, 60);
      T.after(() => line('r', '[' + clock() + '] ALERT: the bait was touched. Nobody should ever do that.'), 1500);
    }
    btn.addEventListener('click', () => { if (scene.classList.contains('caught')) reset(); else run(); });
    Deck.register('honeypot', {
      enter() { reset(); },
      leave() { reset(); },
      step(n, jump) { if (n >= 1 && !jump) run(); if (n === 0) reset(); },
    });
  })();

  /* ================================================================== 05 cowrie */
  (function () {
    const body = $('#tb'), input = $('#ti'), form = $('#tf'), rec = $('#reclog');
    const OUT = {
      'whoami': 'root',
      'id': 'uid=0(root) gid=0(root) groups=0(root)',
      'pwd': '/root',
      'ls': 'Desktop  Documents  backup.tar.gz  notes.txt',
      'uname -a': 'Linux svr04 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux',
      'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000::/home/admin:/bin/bash',
      'help': 'try: whoami  uname -a  ls  cat /etc/passwd  wget <url>  id  pwd',
    };
    const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    function add(cls, text) {
      const d = document.createElement('div'); d.className = cls; d.textContent = text; body.appendChild(d);
      while (body.children.length > 9) body.removeChild(body.firstChild);
    }
    function record(kind, detail) {
      const d = document.createElement('div');
      d.innerHTML = '<span class="k">' + kind + '</span> <span class="v">' + esc(detail) + '</span> session=a3f91c0d22b1';
      rec.appendChild(d);
      while (rec.children.length > 6) rec.removeChild(rec.firstChild);
    }
    function reset() {
      body.innerHTML = ''; rec.innerHTML = ''; input.value = '';
      add('m', 'Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)');
      add('m', 'Last login: Fri Nov 13 10:02:14 2026 from 203.0.113.10');
      record('cowrie.session.connect', 'src_ip=203.0.113.10');
      record('cowrie.login.success', 'root / P*********');
    }
    function exec(cmd) {
      cmd = cmd.trim();
      if (!cmd) return;
      add('o', '');
      body.lastChild.innerHTML = '<span class="p">root@svr04:~#</span> ' + esc(cmd);
      record('cowrie.command.input', '"' + cmd + '"');
      if (cmd === 'clear') { body.innerHTML = ''; return; }
      let out = OUT[cmd];
      if (!out && /^wget\s+\S+/.test(cmd)) out = "Connecting… connected.\nSaving to: 'x'\n'x' saved [1024/1024]";
      if (out) add('o', out);
      else add('e', 'bash: ' + cmd.split(/\s+/)[0] + ': command not found');
    }
    form.addEventListener('submit', (e) => { e.preventDefault(); exec(input.value); input.value = ''; });
    $$('#cmdchips .chipbtn').forEach((b) => b.addEventListener('click', () => exec(b.dataset.cmd)));
    let started = false;
    Deck.register('cowrie', { enter() { if (!started) { reset(); started = true; } }, leave() { input.blur(); } });
  })();

  /* ================================================================ 06 vocabulary */
  (function () {
    const T = Deck.timers();
    const box = $('#vdemo');
    const tiles = $$('#vtiles .vtile');
    const al = 'abcdefghijklmnopqrstuvwxyz';
    const word = (k) => { let s = ''; for (let i = 0; i < 5; i++) { s = al[k % 26] + s; k = Math.floor(k / 26); } return s; };
    const sleep = (ms) => new Promise((r) => T.after(r, ms));
    let token = 0;

    const DEMOS = {
      brute(b) {
        b.innerHTML = '<div class="vd"><div class="vd-col"><div class="vd-head">the attacker’s script is guessing…</div><div class="vd-big" id="vb-g">aaaaa</div><div class="vd-sub">aaaaa → aaaab → aaaac → … every combination, in order</div></div><div class="vd-col"><div class="vd-head">tries so far</div><div class="vd-num" id="vb-n">0</div><div class="vd-sub">A script never gets tired: thousands of tries per second.</div></div></div>';
        let k = Math.floor(rnd(0, 300000)), n = 0;
        const g = $('#vb-g'), c = $('#vb-n');
        T.every(() => { k += 1; n += 137; g.textContent = word(k); c.textContent = n.toLocaleString('en-US'); }, 55);
      },
      async dict(b, tk) {
        const pw = ['123456', 'password', 'qwerty', 'letmein', 'admin', 'welcome'];
        b.innerHTML = '<div class="vd"><div class="vd-col"><div class="vd-head">most common passwords first</div><div class="pwchips" id="pwc"></div></div><div class="vd-col"><div class="vd-big small" id="vd-res">searching…</div><div class="vd-sub">Many people choose predictable passwords, so attackers start there. It takes seconds.</div></div></div>';
        const c = $('#pwc'), res = $('#vd-res');
        while (tk === token) {
          c.innerHTML = ''; res.textContent = 'searching…'; res.className = 'vd-big small';
          for (let i = 0; i < pw.length; i++) {
            const s = document.createElement('span'); s.className = 'pw'; s.textContent = pw[i]; c.appendChild(s);
            await sleep(420); if (tk !== token) return;
            const hit = i === pw.length - 1;
            s.classList.add(hit ? 'ok' : 'bad'); s.textContent = pw[i] + (hit ? '  ✓' : '  ✗');
          }
          res.textContent = 'a weak password was found'; res.className = 'vd-big small bad';
          await sleep(2600);
        }
      },
      async spray(b, tk) {
        const users = ['root', 'admin', 'ubuntu', 'pi', 'test', 'oracle'];
        const pws = ['Summer2026!', 'Welcome1'];
        let html = '<div class="vd"><div class="vd-col wide"><div class="vd-head">the same password, one account after another</div><table class="spray"><tr><th></th>' + users.map((u) => '<th>' + u + '</th>').join('') + '</tr>';
        pws.forEach((p, r) => { html += '<tr><td class="pwl">' + p + '</td>' + users.map((u, c) => '<td><i id="sp-' + r + '-' + c + '"></i></td>').join('') + '</tr>'; });
        html += '</table></div><div class="vd-col"><div class="vd-sub big">Only <b>1 attempt per account</b>: no lockout, no alarm. Then the next password.</div></div></div>';
        b.innerHTML = html;
        while (tk === token) {
          $$('.spray i').forEach((i) => { i.className = ''; i.textContent = ''; });
          for (let r = 0; r < pws.length; r++) {
            for (let c = 0; c < users.length; c++) {
              const cell = $('#sp-' + r + '-' + c); if (!cell) return;
              cell.className = 'x'; cell.textContent = '✗';
              await sleep(260); if (tk !== token) return;
            }
          }
          await sleep(2200);
        }
      },
      async enum(b, tk) {
        const rows = [['root', 1], ['alice', 0], ['admin', 1], ['bob', 0], ['pi', 1]];
        b.innerHTML = '<div class="vd"><div class="vd-col"><div class="vd-head">does this account exist?</div><div class="erows" id="er"></div></div><div class="vd-col"><div class="vd-big small" id="er-res">probing…</div><div class="vd-sub">The server’s reply leaks which accounts are real. Now the attacker knows who to target.</div></div></div>';
        const list = $('#er'), res = $('#er-res');
        while (tk === token) {
          list.innerHTML = ''; res.textContent = 'probing…'; res.className = 'vd-big small';
          let found = 0;
          for (const [u, ok] of rows) {
            const d = document.createElement('div'); d.className = 'erow ' + (ok ? 'yes' : 'no');
            d.innerHTML = '<code>' + u + '</code><span>' + (ok ? '✓ exists' : '✗ no such user') + '</span>'; list.appendChild(d);
            if (ok) found += 1;
            await sleep(480); if (tk !== token) return;
          }
          res.textContent = found + ' valid accounts found'; res.className = 'vd-big small bad';
          await sleep(2600);
        }
      },
      async session(b, tk) {
        b.innerHTML = '<div class="vd"><div class="vd-col wide"><div class="vd-head">one SSH session</div><div class="tl"><div class="tln" id="tl0"><i></i><b>CONNECT</b><small>10:02:11</small></div><div class="tln" id="tl1"><i></i><b>LOGIN</b><small>root ✓</small></div><div class="tln" id="tl2"><i></i><b>COMMANDS</b><small>uname · ls · wget</small></div><div class="tln" id="tl3"><i></i><b>CLOSE</b><small>10:02:31</small></div></div></div><div class="vd-col"><div class="vd-big small" id="tl-d">duration …</div><div class="vd-sub">Sentinel groups events by session: when it started, how long it lasted, what was typed.</div></div></div>';
        while (tk === token) {
          $$('.tln').forEach((n) => n.classList.remove('on')); $('#tl-d').textContent = 'duration …';
          for (let i = 0; i < 4; i++) { await sleep(750); if (tk !== token) return; $('#tl' + i).classList.add('on'); }
          $('#tl-d').textContent = 'duration: 20 s';
          await sleep(2600);
        }
      },
    };

    function select(key) {
      T.clear(); token += 1;
      tiles.forEach((t) => t.classList.toggle('sel', t.dataset.v === key));
      if (!key) { box.innerHTML = '<div class="vd-empty">Press → to meet the first one</div>'; return; }
      box.innerHTML = '';
      DEMOS[key](box, token);
    }
    tiles.forEach((t) => t.addEventListener('click', () => { if (t.classList.contains('on')) select(t.dataset.v); }));
    Deck.register('vocab', {
      enter() { select(null); },
      leave() { T.clear(); token += 1; },
      step(n) { select(n >= 1 ? tiles[n - 1].dataset.v : null); },
    });
  })();
})();
