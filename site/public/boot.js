// "Give Gary the boot": plays the kick, then offers to let him back in.
(() => {
  const btn = document.getElementById('kick');
  const note = document.getElementById('kick-note');
  const scene = document.querySelector('.boot-scene');
  if (!btn || !scene) return;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let out = false;

  btn.addEventListener('click', () => {
    if (out) {
      scene.classList.remove('kicked');
      scene.setAttribute('aria-label', 'Gary the pig, in sunglasses, standing inside the fence, about to be booted over it.');
      btn.textContent = 'Give Gary the boot';
      note.textContent = 'Fine. One more chance, Gary.';
      out = false;
      return;
    }
    scene.classList.add('kicked');
    btn.disabled = true;
    note.textContent = '';
    setTimeout(() => {
      out = true;
      btn.disabled = false;
      btn.textContent = 'Let Gary back in';
      scene.setAttribute('aria-label', 'Gary the pig, now outside the fence, sitting in the mud.');
      note.textContent = 'Gary is outside. That took 2.1 seconds, same as the real thing.';
    }, reduced ? 0 : 2700);
  });
})();
