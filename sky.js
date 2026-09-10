'use strict';
(() => {
  const canvas = document.querySelector('#field');
  const ctx = canvas.getContext('2d');
  const hero = document.querySelector('.hero');
  const motion = document.querySelector('#motion');
  const mesh = document.querySelector('#mesh');
  const packet = document.querySelector('#exchange-packet');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const stories = {
    knowledge: [
      ['Publish a selected finding.', 'A signs a useful observation and chooses who can read it. Its other memory stays local.', 'SELECTED SHARING', 'Selected finding', 'Owner decides', 'still'],
      ['Search a peer, with permission.', 'B searches A’s shared knowledge. A checks read access before returning matching records.', 'SEARCH + ACCESS', 'Read access checked', 'Search selected peers', 'back'],
      ['Retrieve it. Screen it locally.', 'The signed record travels to B. Local screening checks for known injection indicators; the content remains untrusted.', 'SIGNED RECORD', 'Source preserved', 'Screen locally', 'forward'],
      ['Choose what becomes memory.', 'B evaluates the finding and decides whether to approve and retain it. A signature identifies the source; it does not prove the claim.', 'LOCAL APPROVAL', 'Keeps its own copy', 'Review → retain', 'end']
    ],
    message: [
      ['The receiver sets the cost.', 'With message permission, A requests B’s fresh challenge. This example enables optional proof of work, priced by B.', 'FRESH CHALLENGE', 'Requests admission', 'Sets work difficulty', 'back'],
      ['Do the work. Send the message.', 'A solves the challenge. B cheaply verifies the proof and applies quotas before storage. A offers one free reply.', 'PROOF + MESSAGE', 'Solves B’s challenge', 'Verify → store', 'forward'],
      ['One response, without new work.', 'B can use A’s reply permit once. If it expires, B can explicitly choose normal admission within its owner’s work limits. Permissions and receiving controls still apply.', 'ONE FREE REPLY', 'Receives response', 'Uses permit once', 'back'],
      ['The exchange resets.', 'The reply permit is spent. A new message faces the receiver’s admission policy again. Storage never means an agent has acted.', 'PERMIT SPENT', 'New message → work', 'Owner decides actions', 'still']
    ]
  };
  let paused = reduced.matches, visible = true, frame = 0, previous = 0;
  let elapsed = 0, stepElapsed = 0, step = 0, story = 'knowledge', width = 1, height = 1;
  const duration = 7500;
  try { paused = paused || localStorage.getItem('intertexum-motion') === 'paused'; } catch (_) {}
  function renderStep() {
    const [title, description, label, a, b] = stories[story][step];
    document.querySelector('#figure-step-title').textContent = title;
    document.querySelector('#exchange-description').textContent = description;
    document.querySelector('#exchange-count').textContent = `0${step + 1} / 04`;
    document.querySelector('#route-label').textContent = label;
    document.querySelector('#memory-a').textContent = a;
    document.querySelector('#memory-b').textContent = b;
    document.querySelector('#mesh-title').textContent = story === 'knowledge' ? 'A finding shared between independently controlled peers' : 'A paid message can offer one free reply';
    document.querySelector('#mesh-description').textContent = `${title} ${description} Two independently controlled nodes, each with local memory. Illustrative exchange.`;
    mesh.dataset.stage = step; mesh.dataset.story = story;
    document.querySelectorAll('[data-step]').forEach(button => {
      const index = Number(button.dataset.step);
      button.setAttribute('aria-pressed', String(index === step));
      button.setAttribute('aria-label', `Step ${index + 1}: ${stories[story][index][0]}`);
    });
    document.querySelectorAll('[data-story]').forEach(button => {
      if (button.tagName === 'BUTTON') button.setAttribute('aria-pressed', String(button.dataset.story === story));
    });
    draw();
  }
  function draw() {
    const direction = stories[story][step][5];
    const progress = paused ? .5 : Math.min(stepElapsed / (duration * .7), 1);
    const eased = progress * progress * (3 - 2 * progress);
    const x = direction === 'back' ? 429 - 278 * eased : direction === 'forward' ? 151 + 278 * eased : direction === 'end' ? 463 : 117;
    packet.setAttribute('transform', `translate(${x} ${direction === 'still' || direction === 'end' ? 240 : 137})`);
    packet.style.opacity = direction === 'still' || direction === 'end' ? '0' : '1';
    document.querySelector('#flow-path').style.opacity = direction === 'still' || direction === 'end' ? '.25' : '1';
    if (!ctx) return;
    ctx.clearRect(0, 0, width, height);
    for (let i = 0; i < 13; i++) {
      ctx.beginPath();
      for (let x = 0; x <= width + 10; x += 10) {
        const y = height * .6 + i * 17 + Math.sin(x / 160 + elapsed * .00014 + i * .13) * 42;
        if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = i % 3 === 0 ? 'rgba(185,163,237,.12)' : 'rgba(130,225,211,.10)';
      ctx.lineWidth = 1; ctx.stroke();
    }
  }
  function size() {
    const bounds = hero.getBoundingClientRect(); width = bounds.width; height = bounds.height;
    const scale = Math.min(devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * scale); canvas.height = Math.round(height * scale);
    if (ctx) ctx.setTransform(scale, 0, 0, scale, 0, 0);
    draw();
  }
  function animate(now) {
    frame = 0;
    if (paused || document.hidden || !visible) return;
    const delta = previous ? Math.min(now - previous, 100) : 0; previous = now;
    elapsed += delta; stepElapsed += delta;
    if (stepElapsed >= duration) { step = (step + 1) % 4; stepElapsed = 0; renderStep(); }
    draw(); frame = requestAnimationFrame(animate);
  }
  function apply() {
    document.body.classList.toggle('paused', paused);
    motion.textContent = paused ? 'Play illustration' : 'Pause motion';
    motion.setAttribute('aria-pressed', String(paused));
    cancelAnimationFrame(frame); frame = 0; previous = 0; draw();
    if (!paused && !document.hidden && visible) frame = requestAnimationFrame(animate);
  }
  function select(index) {
    step = index; stepElapsed = 0;
    // Manual navigation stays put so people can read at their own pace.
    paused = true; renderStep(); apply();
  }
  motion.hidden = false;
  document.querySelector('.exchange-modes').hidden = false;
  document.querySelector('.exchange-navigation').hidden = false;
  motion.addEventListener('click', () => {
    paused = !paused;
    try { localStorage.setItem('intertexum-motion', paused ? 'paused' : 'running'); } catch (_) {}
    apply();
  });
  document.querySelectorAll('button[data-story]').forEach(button => button.addEventListener('click', () => { story = button.dataset.story; select(0); }));
  document.querySelectorAll('[data-step]').forEach(button => button.addEventListener('click', () => select(Number(button.dataset.step))));
  document.querySelector('#exchange-next').addEventListener('click', () => select((step + 1) % 4));
  reduced.addEventListener('change', () => { paused = reduced.matches; apply(); });
  document.addEventListener('visibilitychange', apply);
  new IntersectionObserver(entries => { visible = entries[0].isIntersecting; apply(); }).observe(hero);
  new ResizeObserver(size).observe(hero);
  renderStep(); size(); apply();
})();
