(() => {
  'use strict';
  const root = document.querySelector('.journey');
  const stages = [...root.querySelectorAll('.stage')];
  const links = [...root.querySelectorAll('[data-step]')];
  const names = ['Own your node', 'Find your peers', 'Decide what’s allowed', 'Open a conversation', 'Share a memory', 'Learn a withdrawal'];
  const play = document.querySelector('#play');
  const motion = document.querySelector('#motion');
  const previous = document.querySelector('#previous');
  const next = document.querySelector('#next');
  const status = document.querySelector('#journey-status');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  let current = 0;
  let timer = null;
  let playing = false;
  let paused = reduced.matches;
  try { paused = reduced.matches || localStorage.getItem('intertexum-motion') === 'paused'; } catch (_) {}

  function updatePlayback() {
    clearTimeout(timer);
    play.textContent = playing ? 'Pause walkthrough Ⅱ' : 'Play walkthrough ▶';
    play.setAttribute('aria-pressed', String(playing));
    motion.textContent = paused ? 'Resume motion' : 'Pause motion';
    motion.setAttribute('aria-pressed', String(paused));
    document.body.classList.toggle('paused', paused || document.hidden);
    if (playing && !document.hidden) timer = setTimeout(() => {
      if (current < stages.length - 1) show(current + 1, false, true);
      else { playing = false; updatePlayback(); }
    }, 12000);
  }
  function show(index, updateHash = true, automatic = false) {
    current = Math.max(0, Math.min(index, stages.length - 1));
    stages.forEach((stage, i) => { stage.hidden = i !== current; });
    links.forEach((link, i) => {
      if (i === current) link.setAttribute('aria-current', 'step');
      else link.removeAttribute('aria-current');
    });
    document.querySelector('#step-count').textContent = `0${current + 1} / 06`;
    status.textContent = `Step ${current + 1} of 6: ${names[current]}.`;
    previous.disabled = current === 0;
    next.disabled = current === stages.length - 1;
    if (updateHash) history.replaceState(null, '', `#step-${current + 1}`);
    if (!automatic) playing = false;
    updatePlayback();
  }
  function choose(index) {
    show(index);
    if (matchMedia('(max-width: 800px)').matches) {
      stages[current].scrollIntoView({block:'start', behavior:paused ? 'auto' : 'smooth'});
    }
  }
  links.forEach((link, i) => link.addEventListener('click', event => { event.preventDefault(); choose(i); }));
  previous.addEventListener('click', () => choose(current - 1));
  next.addEventListener('click', () => choose(current + 1));
  play.addEventListener('click', () => {
    if (!playing && current === stages.length - 1) show(0);
    playing = !playing;
    updatePlayback();
  });
  motion.addEventListener('click', () => {
    paused = !paused;
    if (paused) playing = false;
    try { localStorage.setItem('intertexum-motion', paused ? 'paused' : 'running'); } catch (_) {}
    updatePlayback();
  });
  reduced.addEventListener('change', () => { paused = reduced.matches; playing = false; updatePlayback(); });
  document.addEventListener('visibilitychange', updatePlayback);
  // User focus inside a step pauses progression so controls cannot disappear mid-use.
  document.querySelector('.stages').addEventListener('focusin', () => { playing = false; updatePlayback(); });
  window.addEventListener('hashchange', () => {
    const match = location.hash.match(/^#step-([1-6])$/);
    if (match) show(Number(match[1]) - 1, false);
  });
  const set = (selector, text) => { document.querySelector(selector).textContent = text; };
  document.querySelectorAll('[data-choice]').forEach(group => {
    group.hidden = false;
    group.addEventListener('click', event => {
      const button = event.target.closest('button');
      if (!button || !group.contains(button)) return;
      playing = false;
      updatePlayback();
      group.querySelectorAll('button').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
      const kind = group.dataset.choice;
      const value = button.dataset.value;
      const diagram = document.querySelector(`[data-demo="${kind}"]`);
      diagram.dataset.mode = value;
      if (kind === 'discovery') {
        const lan = value === 'lan';
        set('[data-discovery-label]', lan ? 'Local discovery · IPv4 mDNS' : 'Bootstrap nodes · introductions');
        set('[data-discovery-description]', lan ? 'Running nodes with the same network name announce themselves on the LAN.' : 'Trusted bootstrap nodes forward signed introductions and help peers arrange a connection.');
        set('[data-discovery-foot]', lan ? 'No bootstrap node is required for this local network example.' : 'Bootstrap nodes introduce peers. Messages and memory use peer connections or an encrypted relay path.');
      } else if (kind === 'membership') {
        const open = value === 'public';
        set('[data-member-title]', open ? 'Discovered identity' : 'Prove membership');
        set('[data-member-description]', open ? 'Public access only' : 'Proof of the shared invitation');
        set('[data-member-proof]', open ? 'No shared membership secret' : 'Invitation secret is never broadcast');
        const permission = document.querySelector('[data-private-permission]');
        permission.replaceChildren();
        const marker = document.createElement('span');
        marker.className = open ? 'grant' : 'check';
        marker.textContent = open ? '+' : '✓';
        permission.append(marker, document.createTextNode(open ? 'Private access needs a grant' : 'Configured membership permissions'));
        set('[data-member-foot]', open ? 'A grant on B permits A’s requests to B. The reverse direction is separate.' : 'Every invitation holder can share that secret with another participant. Permissions follow the receiver’s profile.');
        // A private invitation does not promise public-profile enrollment semantics.
        const firstPermission = diagram.querySelector('.permission-list li:first-child');
        firstPermission.replaceChildren();
        const firstMarker = document.createElement('span'); firstMarker.className = 'check'; firstMarker.textContent = '✓';
        firstPermission.append(firstMarker, document.createTextNode(open ? 'Public memory & threads' : 'Verified shared-key membership'));
      } else if (kind === 'transport') {
        const direct = value === 'direct';
        set('[data-transport-label]', direct ? 'Mutual TLS 1.3' : 'Encrypted DTLS traffic');
        diagram.querySelector('.relay-chip').hidden = direct;
        set('[data-transport-foot]', direct ? 'Each side verifies the other’s identity; TLS encrypts the direct connection. ICE can arrange another encrypted direct path when needed.' : 'A configured relay server (TURN) forwards encrypted traffic. Bootstrap nodes handle introductions separately.');
      }
      status.textContent = `${names[current]}: ${button.textContent}. Illustration updated.`;
    });
  });
  document.querySelector('#sync-withdrawal').addEventListener('click', event => {
    const diagram = document.querySelector('[data-demo="withdrawal"]');
    const learned = diagram.dataset.mode !== 'learned';
    diagram.dataset.mode = learned ? 'learned' : 'offline';
    diagram.querySelector('.wire').classList.toggle('broken', !learned);
    set('[data-withdraw-label]', learned ? 'Sync withdrawal' : 'Peer is offline');
    set('[data-withdraw-title]', learned ? 'Withdrawal learned' : 'Has not learned yet');
    set('[data-withdraw-description]', learned ? 'Record and affected descendants become unavailable' : 'An eligible old copy may still be served');
    set('[data-withdraw-small]', learned ? 'Retain the signed withdrawal' : 'No instantaneous global recall');
    event.currentTarget.textContent = learned ? 'Reset illustration ↺' : 'Simulate reconnection ↗';
    status.textContent = learned ? 'Illustration: Node B learned the withdrawal and stops serving the record and affected descendants.' : 'Illustration reset: Node B has not learned the withdrawal yet.';
  });
  root.classList.add('enhanced');
  document.querySelector('.playback').hidden = false;
  document.querySelector('.step-footer').hidden = false;
  document.querySelector('.simulation-control').hidden = false;
  const match = location.hash.match(/^#step-([1-6])$/);
  show(match ? Number(match[1]) - 1 : 0, false);
})();
