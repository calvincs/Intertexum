(() => {
  'use strict';
  const search = document.querySelector('#doc-search');
  if (search) {
    document.querySelector('.doc-filter').hidden = false;
    const cards = [...document.querySelectorAll('[data-doc-card]')];
    search.addEventListener('input', () => {
      const terms = search.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
      let count = 0;
      cards.forEach(card => {
        const text = card.querySelector('a').textContent.toLocaleLowerCase();
        card.hidden = !terms.every(term => text.includes(term));
        if (!card.hidden) count++;
      });
      document.querySelectorAll('[data-doc-category]').forEach(group => {
        group.hidden = ![...group.querySelectorAll('[data-doc-card]')].some(card => !card.hidden);
      });
      document.querySelector('#no-doc-results').hidden = count > 0;
      document.querySelector('#filter-status').textContent = terms.length ? `${count} of ${cards.length} guides match.` : '';
    });
  }

  // Native disclosure controls keep navigation available without JavaScript.
  if (matchMedia('(max-width: 800px)').matches) {
    document.querySelectorAll('.doc-browse, .doc-toc details').forEach(details => { details.open = false; });
  } else if (matchMedia('(max-width: 1150px)').matches) {
    const toc = document.querySelector('.doc-toc details');
    if (toc) toc.open = false;
  }

  if (navigator.clipboard && window.isSecureContext) {
    document.querySelectorAll('.prose pre').forEach(pre => {
      const frame = document.createElement('div');
      frame.className = 'code-frame';
      pre.before(frame);
      frame.append(pre);
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'code-copy';
      button.textContent = 'Copy code';
      button.setAttribute('aria-label', 'Copy code block');
      button.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(pre.textContent);
          button.textContent = 'Copied';
        } catch {
          button.textContent = 'Select text to copy';
        }
        setTimeout(() => { button.textContent = 'Copy code'; }, 2200);
      });
      frame.append(button);
    });
  }

  const motionButtons = [...document.querySelectorAll('.diagram-motion')];
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  let paused = reduced.matches;
  try { paused = paused || localStorage.getItem('intertexum-motion') === 'paused'; } catch { /* Optional preference. */ }
  const paintMotion = () => {
    document.body.classList.toggle('docs-motion', !paused && !reduced.matches);
    motionButtons.forEach(button => {
      button.hidden = reduced.matches;
      button.setAttribute('aria-pressed', String(paused));
      button.textContent = paused ? 'Resume motion' : 'Pause motion';
    });
  };
  motionButtons.forEach(button => button.addEventListener('click', () => {
    paused = !paused;
    try { localStorage.setItem('intertexum-motion', paused ? 'paused' : 'running'); } catch { /* Optional preference. */ }
    paintMotion();
  }));
  reduced.addEventListener('change', paintMotion);
  paintMotion();

  if ('IntersectionObserver' in window) {
    const links = [...document.querySelectorAll('.doc-toc a[href^="#"]')];
    const headings = [...document.querySelectorAll('.prose h2[id], .prose h3[id]')];
    const observer = new IntersectionObserver(entries => {
      const visible = entries.filter(entry => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
      if (!visible.length) return;
      const id = visible[0].target.id;
      links.forEach(a => {
        if (decodeURIComponent(a.hash.slice(1)) === id) a.setAttribute('aria-current', 'location');
        else a.removeAttribute('aria-current');
      });
    }, {rootMargin: '0px 0px -65% 0px'});
    headings.forEach(heading => observer.observe(heading));
  }
})();
