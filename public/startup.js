// Loading and initialization only; no password data, diagnostics or telemetry.
export async function initializeApplication(load = () => import('./app.js'), page = document) {
  let ready = false;
  const form = page.getElementById('settings-form');
  // A partial initialization must not leave a working submission handler.
  form?.addEventListener('submit', event => {
    if (!ready) { event.preventDefault(); event.stopImmediatePropagation(); }
  }, true);
  try {
    const stylesheet = page.querySelector?.('link[rel="stylesheet"]');
    if (stylesheet && page.defaultView) {
      if (page.readyState !== 'complete') await new Promise(resolve => page.defaultView.addEventListener('load', resolve, {once:true}));
      // Some browsers retain an empty CSSStyleSheet object after an HTTP error.
      if (!stylesheet.sheet || !stylesheet.sheet.cssRules.length) throw new Error('Required stylesheet unavailable.');
    }
    await load();
    ready = true;
    return true;
  } catch {
    for (const id of ['generate', 'batch-generate', 'settings-generate']) {
      const control = page.getElementById(id);
      if (control) control.disabled = true;
    }
    const status = page.getElementById('status');
    if (status) status.textContent = 'Zevyrn could not load. Reload the page to try again. Password generation is unavailable.';
    return false;
  }
}
if (typeof document !== 'undefined') void initializeApplication();
