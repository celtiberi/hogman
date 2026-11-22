// Add a 1-click Copy button to command blocks inside /docs/.
(() => {
  if (!navigator.clipboard) return;
  document.querySelectorAll('.docs-main pre.term').forEach((pre) => {
    const raw = pre.textContent || '';
    const cmdLines = raw
      .split('\n')
      .map((l) => l.trimEnd())
      .filter((l) => l.startsWith('$ '));
    if (!cmdLines.length) return;
    const text = cmdLines.map((l) => l.slice(2)).join('\n');

    const wrap = document.createElement('div');
    wrap.className = 'term-wrap';
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.setAttribute('aria-label', 'Copy command');
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = 'Copy';
          btn.classList.remove('copied');
        }, 1600);
      }).catch(() => {});
    });
    wrap.appendChild(btn);
  });
})();
