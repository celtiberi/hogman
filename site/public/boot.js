// "Give Gary the boot": the painting sits dim and grey until the kick lands,
// then a clock runs to 2.1 seconds, which is how long the real thing took.
(() => {
  const btn = document.getElementById('kick');
  const note = document.getElementById('kick-note');
  const art = document.getElementById('boot-art');
  const clock = document.getElementById('clock');
  if (!btn || !art || !clock) return;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const TOTAL = 2100;
  let out = false;

  const finish = () => {
    clock.textContent = '2.1';
    art.classList.add('done');
    out = true;
    btn.disabled = false;
    btn.textContent = 'Let Gary back in';
    note.textContent = 'Gary is outside. That took 2.1 seconds, same as the real thing.';
  };

  btn.addEventListener('click', () => {
    if (out) {
      art.classList.remove('kicked', 'done');
      clock.textContent = '0.0';
      btn.textContent = 'Give Gary the boot';
      note.textContent = 'Fine. One more chance, Gary.';
      out = false;
      return;
    }
    art.classList.add('kicked');
    btn.disabled = true;
    note.textContent = '';
    if (reduced) return finish();
    const start = performance.now();
    const tick = (now) => {
      const t = Math.min(now - start, TOTAL);
      clock.textContent = (t / 1000).toFixed(1);
      if (t < TOTAL) requestAnimationFrame(tick); else finish();
    };
    requestAnimationFrame(tick);
  });
})();
