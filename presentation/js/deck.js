/* =========================================================================
   Tiny presentation engine (no dependencies, works offline from a file).
   - 1280x720 stage scaled to fit any screen
   - arrow keys / space / swipe / on-screen arrows
   - "steps": each press of -> reveals the next element before changing slide
   - O = overview, F = fullscreen, Home / End
   Slide modules register with Deck.register(id, { enter, leave, step }).
   ========================================================================= */
(function () {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  window.$ = $; window.$$ = $$;

  const stage = $('#stage');
  const slides = $$('.slide');
  const bar = $('#bar');
  const counter = $('#counter');
  const modules = {};
  let cur = -1;
  let stepNow = 0;

  const Deck = window.Deck = {
    scale: 1,
    register(id, mod) { modules[id] = mod; },
    get index() { return cur; },
    get step() { return stepNow; },
    get id() { return slides[cur] && slides[cur].id; },

    /* helper: a bag of timers that can be cancelled all at once */
    timers() {
      const ids = [];
      return {
        after(fn, ms) { const id = setTimeout(fn, ms); ids.push(id); return id; },
        every(fn, ms) { const id = setInterval(fn, ms); ids.push(id); return id; },
        clear() { ids.forEach((id) => { clearTimeout(id); clearInterval(id); }); ids.length = 0; },
      };
    },
    /* helper: requestAnimationFrame loop with stop(); fn gets (time, dt) */
    loop(fn) {
      let on = true, last = 0, id;
      const tick = (t) => { if (!on) return; fn(t, t - last); last = t; id = requestAnimationFrame(tick); };
      id = requestAnimationFrame(tick);
      return () => { on = false; cancelAnimationFrame(id); };
    },
    prefersReducedMotion: window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches,
  };

  /* ---------------------------------------------------------------- scaling */
  function fit() {
    const s = Math.min(window.innerWidth / 1280, window.innerHeight / 720);
    Deck.scale = s;
    stage.style.setProperty('--s', s);
  }
  window.addEventListener('resize', fit);
  fit();

  /* ------------------------------------------------------------------ steps */
  slides.forEach((sl) => {
    let m = parseInt(sl.dataset.steps || '0', 10);
    $$('[data-step]', sl).forEach((e) => { m = Math.max(m, parseInt(e.dataset.step, 10)); });
    sl._max = m;
  });

  function applyStep(sl, n) {
    $$('[data-step]', sl).forEach((e) => e.classList.toggle('on', parseInt(e.dataset.step, 10) <= n));
    for (let k = 1; k <= sl._max; k++) sl.classList.toggle('step-' + k, k <= n);
    sl.dataset.now = n;
  }

  /* ------------------------------------------------------------- navigation */
  function show(i, step) {
    i = Math.max(0, Math.min(slides.length - 1, i));
    const sl = slides[i];
    if (i !== cur) {
      if (cur >= 0) {
        const old = slides[cur];
        const om = modules[old.id];
        if (om && om.leave) om.leave();
        old.classList.remove('active');
      }
      slides.forEach((s, k) => { if (k !== i) { s.classList.toggle('past', k < i); } });
      sl.classList.remove('past');
      sl.classList.add('active');
      cur = i;
      stepNow = step === 'max' ? sl._max : (step || 0);
      applyStep(sl, stepNow);
      const m = modules[sl.id];
      if (m && m.enter) m.enter({ back: step === 'max' });
      if (m && m.step) m.step(stepNow, true);
      bar.style.width = ((i + 1) / slides.length * 100) + '%';
      counter.textContent = String(i + 1).padStart(2, '0') + ' / ' + String(slides.length).padStart(2, '0');
      history.replaceState(null, '', '#' + (i + 1));
      $$('.ov-item').forEach((b, k) => b.classList.toggle('cur', k === i));
    } else {
      stepNow = step === 'max' ? sl._max : (step || 0);
      applyStep(sl, stepNow);
      const m = modules[sl.id];
      if (m && m.step) m.step(stepNow, true);
    }
  }

  function next() {
    const sl = slides[cur];
    if (stepNow < sl._max) {
      stepNow += 1;
      applyStep(sl, stepNow);
      const m = modules[sl.id];
      if (m && m.step) m.step(stepNow, false);
    } else if (cur < slides.length - 1) {
      show(cur + 1, 0);
    }
  }
  function prev() {
    const sl = slides[cur];
    if (stepNow > 0) {
      stepNow -= 1;
      applyStep(sl, stepNow);
      const m = modules[sl.id];
      if (m && m.step) m.step(stepNow, true);
    } else if (cur > 0) {
      show(cur - 1, 'max');
    }
  }
  Deck.next = next; Deck.prev = prev; Deck.goto = (i) => show(i, 0);

  /* --------------------------------------------------------------- overview */
  const ov = $('#overview');
  function buildOverview() {
    const grid = $('#ov-grid');
    slides.forEach((s, k) => {
      const b = document.createElement('button');
      b.className = 'ov-item';
      b.innerHTML = '<b>' + String(k + 1).padStart(2, '0') + '</b>' + (s.dataset.title || s.id);
      b.addEventListener('click', () => { toggleOverview(false); show(k, 0); });
      grid.appendChild(b);
    });
  }
  function toggleOverview(force) {
    const open = typeof force === 'boolean' ? force : ov.classList.contains('hidden');
    ov.classList.toggle('hidden', !open);
  }

  function toggleFullscreen() {
    if (!document.fullscreenElement) document.documentElement.requestFullscreen && document.documentElement.requestFullscreen();
    else document.exitFullscreen && document.exitFullscreen();
  }

  /* ----------------------------------------------------------------- input */
  window.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT');
    if (e.key === 'Escape') { toggleOverview(false); if (typing) t.blur(); return; }
    if (typing) { if (t.type === 'range' && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) { /* let sliders use arrows */ } return; }
    const onButton = t && (t.tagName === 'BUTTON' || t.tagName === 'A');
    switch (e.key) {
      case 'ArrowRight': case 'PageDown': next(); e.preventDefault(); break;
      case ' ': case 'Enter': if (onButton) return; next(); e.preventDefault(); break;
      case 'ArrowLeft': case 'PageUp': case 'Backspace': prev(); e.preventDefault(); break;
      case 'Home': show(0, 0); break;
      case 'End': show(slides.length - 1, 'max'); break;
      case 'o': case 'O': toggleOverview(); break;
      case 'f': case 'F': toggleFullscreen(); break;
      default:
    }
  });
  $('#next').addEventListener('click', next);
  $('#prev').addEventListener('click', prev);

  let sx = null, sy = null;
  stage.addEventListener('pointerdown', (e) => { sx = e.clientX; sy = e.clientY; });
  stage.addEventListener('pointerup', (e) => {
    if (sx === null) return;
    const dx = e.clientX - sx, dy = e.clientY - sy;
    sx = sy = null;
    if (Math.abs(dx) > 70 && Math.abs(dx) > Math.abs(dy) * 1.6) { dx < 0 ? next() : prev(); }
  });

  /* ---------------------------------------------------------------- start */
  Deck.start = function () {
    buildOverview();
    document.addEventListener('click', e => { const b = e.target.closest('button, .btn, a'); if (b && b.blur) setTimeout(() => b.blur(), 0); });
    let first = parseInt((location.hash || '').slice(1), 10);
    if (!(first >= 1 && first <= slides.length)) first = 1;
    show(first - 1, 0);
    setTimeout(() => { const h = $('#hintkeys'); if (h) h.classList.add('fade'); }, 9000);
  };
})();
