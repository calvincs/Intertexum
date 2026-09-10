'use strict';
(() => {
  const canvas = document.querySelector('#field');
  const ctx = canvas.getContext('2d');
  const hero = document.querySelector('.hero');
  const motion = document.querySelector('#motion');
  const trace = document.querySelector('#trace');
  const mesh = document.querySelector('#mesh');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  let paused = reduced.matches, frame = 0, previous = 0, elapsed = 0, timer;
  let width = 1, height = 1;
  try { paused = paused || localStorage.getItem('intertexum-motion') === 'paused'; } catch (_) {}
  function draw() {
    if (!ctx) return;
    ctx.clearRect(0, 0, width, height);
    const phase = elapsed * .00014;
    // Parallel strands form a field, while the SVG explains the peer topology.
    for (let i = 0; i < 13; i++) {
      ctx.beginPath();
      for (let x = 0; x <= width + 10; x += 10) {
        const y = height * .6 + i * 17 + Math.sin(x / 160 + phase + i * .13) * 42;
        if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = i % 3 === 0 ? 'rgba(185,163,237,.12)' : 'rgba(130,225,211,.10)';
      ctx.lineWidth = 1; ctx.stroke();
    }
  }
  function size() {
    const bounds = hero.getBoundingClientRect();
    width = bounds.width; height = bounds.height;
    const scale = Math.min(devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * scale); canvas.height = Math.round(height * scale);
    if (ctx) ctx.setTransform(scale, 0, 0, scale, 0, 0);
    draw();
  }
  function animate(now) {
    frame = 0;
    if (paused || document.hidden || !ctx) return;
    if (now - previous > 40) { elapsed += Math.min(now - previous, 60); previous = now; draw(); }
    frame = requestAnimationFrame(animate);
  }
  function apply() {
    document.body.classList.toggle('paused', paused);
    motion.textContent = paused ? 'Resume motion' : 'Pause motion';
    motion.setAttribute('aria-pressed', String(paused));
    cancelAnimationFrame(frame); frame = 0; draw();
    if (!paused && !document.hidden) frame = requestAnimationFrame(animate);
  }
  motion.hidden = false; trace.hidden = false;
  motion.addEventListener('click', () => {
    paused = !paused;
    try { localStorage.setItem('intertexum-motion', paused ? 'paused' : 'running'); } catch (_) {}
    apply();
  });
  reduced.addEventListener('change', () => { paused = reduced.matches; apply(); });
  document.addEventListener('visibilitychange', apply);
  trace.addEventListener('click', () => {
    clearTimeout(timer); mesh.classList.add('tracing');
    document.querySelector('#trace-status').textContent = 'Illustration: a query goes directly to two selected peers. Only records permitted for the requester can be returned.';
    timer = setTimeout(() => mesh.classList.remove('tracing'), 4500);
  });
  const copy = document.querySelector('#copy'); copy.hidden = false;
  copy.addEventListener('click', async () => {
    const status = document.querySelector('#copy-status');
    try {
      await navigator.clipboard.writeText(document.querySelector('#commands').textContent);
      status.textContent = 'Copied. Supply your trusted network profile before running.';
    } catch (_) { status.textContent = 'Select and copy the commands above; clipboard access is unavailable.'; }
  });
  new ResizeObserver(size).observe(hero); size(); apply();
})();
