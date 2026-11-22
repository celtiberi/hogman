// "Under the hood" audience switcher: pick Stacy or Tech nerd, collapse the picker
// into a compact switch button showing both, click it to pick again.
(() => {
  const pick = document.getElementById('hood-pick');
  const reset = document.getElementById('hood-reset');
  const tabs = Array.from(document.querySelectorAll('[data-hood]'));
  const panels = Array.from(document.querySelectorAll('[data-hood-panel]'));
  if (!pick || !reset || !tabs.length || !panels.length) return;

  const showPicker = () => {
    pick.hidden = false;
    reset.hidden = true;
    panels.forEach((p) => { p.hidden = true; });
    tabs.forEach((t) => {
      t.setAttribute('aria-pressed', 'false');
      t.classList.remove('active');
    });
  };

  const select = (mode) => {
    pick.hidden = true;
    reset.hidden = false;
    tabs.forEach((t) => {
      const on = t.dataset.hood === mode;
      t.setAttribute('aria-pressed', on ? 'true' : 'false');
      t.classList.toggle('active', on);
    });
    panels.forEach((p) => {
      p.hidden = p.dataset.hoodPanel !== mode;
    });
  };

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => select(tab.dataset.hood));
  });
  reset.addEventListener('click', showPicker);
})();
