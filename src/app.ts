import { WORDS } from './dictionary.js';
import { MIN_ENTROPY_BITS, assertSettings, eligibleWords, entropyBits, meetsEntropyPolicy, minimumSuffixLength } from './core.js';
import { policyForProfile, type ProfileRequest, type ReadableProfileSettings } from './profiles.js';
import { analyzePolicy, CATEGORIES, type PolicyError } from './policy.js';
import { PolicyGenerationError } from './random-password.js';
import { prepareProfileOutput, type ProfileOutput } from './profile-output.js';
function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error('Missing interface element.');
  return found as T;
}
const form = element<HTMLFormElement>('settings-form');
const advanced = element<HTMLDetailsElement>('advanced');
const profile = element<HTMLSelectElement>('profile');
// Reveal invalid advanced fields before the browser focuses its validation message.
function invalidSettings(): void {
  if (profile.value === 'readable') advanced.open = true;
  if (profile.value !== 'custom-policy') openSettings();
  synchronizeSettings(); summary();
}
form.addEventListener('invalid', invalidSettings, true);
element('custom-settings').addEventListener('invalid', invalidSettings, true);
const count = element<HTMLSelectElement>('count');
const suffix = element<HTMLInputElement>('suffix');
const min = element<HTMLInputElement>('min-word');
const max = element<HTMLInputElement>('max-word');
const show = element<HTMLInputElement>('show');
const manual = element<HTMLInputElement>('manual');
const list = element<HTMLDivElement>('passwords');
const status = element<HTMLParagraphElement>('status');
const generate = element<HTMLButtonElement>('generate');
const copyAll = element<HTMLButtonElement>('copy-all');
const clearButton = element<HTMLButtonElement>('clear');
interface PasswordEntry { value: string; context: ProfileOutput }
let passwords: PasswordEntry[] = [];
let revision = 0;
let copyAttempt = 0;
const copyLabels = new WeakMap<HTMLButtonElement, string>();
let clipboardWrite: Promise<void> | undefined;
let observedSettings: readonly unknown[] = [];
let keyboardSubmission = false;
const settings = (): ReadableProfileSettings => ({ minWordLength: min.valueAsNumber, maxWordLength: max.valueAsNumber, suffixLength: suffix.valueAsNumber });
function request(): ProfileRequest {
  const groups = (prefix: string) => ({ uppercase: element<HTMLInputElement>(prefix + '-uppercase').checked,
    lowercase: element<HTMLInputElement>(prefix + '-lowercase').checked, digits: element<HTMLInputElement>(prefix + '-digits').checked,
    symbols: element<HTMLInputElement>(prefix + '-symbols').checked });
  switch (profile.value) {
    case 'readable': return { profile: 'readable', settings: settings() };
    case 'strong-random': return { profile: 'strong-random', settings: {
      length: element<HTMLInputElement>('strong-length').valueAsNumber, allowed: groups('strong'),
      excludedCharacters: element<HTMLTextAreaElement>('strong-exclusions').value,
      excludeAmbiguous: element<HTMLInputElement>('strong-ambiguous').checked } };
    case 'custom-policy': return { profile: 'custom-policy', settings: {
      length: element<HTMLInputElement>('custom-length').valueAsNumber, allowed: groups('custom'),
      minimumCounts: { uppercase: element<HTMLInputElement>('custom-min-uppercase').valueAsNumber,
        lowercase: element<HTMLInputElement>('custom-min-lowercase').valueAsNumber,
        digits: element<HTMLInputElement>('custom-min-digits').valueAsNumber, symbols: element<HTMLInputElement>('custom-min-symbols').valueAsNumber },
      permittedSymbols: element<HTMLTextAreaElement>('custom-symbol-list').value,
      excludedCharacters: element<HTMLTextAreaElement>('custom-exclusions').value,
      excludeAmbiguous: element<HTMLInputElement>('custom-ambiguous').checked } };
    default: throw new Error('Choose a supported password profile.');
  }
}
function errorMessage(error: unknown): string {
  if (error instanceof PolicyGenerationError) return policyMessages(error.errors);
  return error instanceof Error ? error.message : 'Invalid settings.';
}
function policyMessages(errors: readonly PolicyError[]): string {
  const labels: Record<string, string> = { length: 'Password length', allowed: 'Permitted categories',
    minimumCounts: 'Required minimum counts', permittedSymbols: 'Allowed symbols', excludedCharacters: 'Excluded characters',
    excludeAmbiguous: 'Ambiguous-character exclusion', 'minimumCounts.uppercase': 'Uppercase minimum',
    'minimumCounts.lowercase': 'Lowercase minimum', 'minimumCounts.digits': 'Numbers minimum', 'minimumCounts.symbols': 'Symbols minimum' };
  return errors.map(item => `${labels[item.field] ? labels[item.field] + ': ' : ''}${item.message}`).join(' ');
}
const policyInputIds = ['suffix', 'min-word', 'max-word', ...['strong', 'custom'].flatMap(prefix =>
  [prefix + '-length', prefix + '-exclusions', prefix + '-ambiguous', ...CATEGORIES.map(id => prefix + '-' + id)]),
  'custom-symbol-list', ...CATEGORIES.map(id => 'custom-min-' + id)];
function resetFieldErrors(): void {
  for (const id of policyInputIds) {
    const message = element(id + '-error');message.textContent = '';message.hidden = true;
    element(id).setAttribute('aria-invalid', 'false');
  }
  element('policy-status').textContent = '';
}
function fieldErrors(errors: readonly PolicyError[]): void {
  const prefix = profile.value === 'strong-random' ? 'strong' : 'custom';
  for (const error of errors) {
    let ids: string[];
    if (profile.value === 'readable') ids = ['suffix', 'min-word', 'max-word'];
    else if (error.field.startsWith('minimumCounts.')) {
      const category = error.field.slice('minimumCounts.'.length);
      ids = [prefix + '-' + category, ...(prefix === 'custom' ? ['custom-min-' + category] : [])];
    } else if (error.field === 'allowed') ids = CATEGORIES.map(id => prefix + '-' + id);
    else if (error.field === 'minimumCounts') ids = CATEGORIES.map(id => 'custom-min-' + id);
    else if (error.field === 'permittedSymbols') ids = ['custom-symbol-list'];
    else if (error.field === 'excludedCharacters') ids = [prefix + '-exclusions'];
    else if (error.field === 'excludeAmbiguous') ids = [prefix + '-ambiguous'];
    else ids = [prefix + '-length'];
    if (error.code === 'INSUFFICIENT_LENGTH' && prefix === 'custom') ids.push(...CATEGORIES.map(id => 'custom-min-' + id));
    if (error.code === 'EMPTY_REQUIRED_CATEGORY') {
      ids.push(prefix + '-exclusions');
      if (prefix === 'custom' && error.field === 'minimumCounts.symbols') ids.push('custom-symbol-list');
    }
    const active = document.activeElement?.id;
    if (error.field === 'policy' && active && policyInputIds.includes(active)) ids.push(active);
    for (const id of new Set(ids)) {
      const message = element(id + '-error');message.hidden = false;
      message.textContent += (message.textContent ? ' ' : '') + error.message;
      element(id).setAttribute('aria-invalid', 'true');
    }
  }
  // Inline descriptions are deliberately not live. Announce one concise state
  // here; the output status is reserved for generation and clipboard actions.
  element('policy-status').textContent = 'Generation blocked. Check the marked settings.';
  // Errors remain signposted outside the dialog; do not steal focus during editing.
  if (profile.value === 'readable') advanced.open = true;
}
function settingsValues(): readonly unknown[] {
  const selected = request();
  if (selected.profile === 'readable') return [selected.profile, count.value,
    selected.settings.minWordLength, selected.settings.maxWordLength, selected.settings.suffixLength];
  const s = selected.settings!; // request() supplies all DOM settings explicitly.
  return [selected.profile, count.value, s.length, ...CATEGORIES.map(id => s.allowed[id]),
    s.excludedCharacters, s.excludeAmbiguous, ...(selected.profile === 'custom-policy'
      ? [selected.settings.permittedSymbols, ...CATEGORIES.map(id => selected.settings.minimumCounts[id])] : [])];
}
function synchronizeSettings(): boolean {
  // DOM property assignments need not emit input/change. Recheck before every
  // password action without polling, patching setters, or serializing raw text.
  let values: readonly unknown[];
  try { values = settingsValues(); } catch { settingsChanged(); return true; }
  if (values.length === observedSettings.length && values.every((v, i) => Object.is(v, observedSettings[i]))) return false;
  settingsChanged();return true;
}
function ensureResultVisible(output = list.querySelector?.<HTMLElement>('.password'), keyboard = false): boolean {
  if (!output?.getBoundingClientRect || typeof window.innerHeight !== 'number') return false;
  const box = output.getBoundingClientRect();
  const visible = box.top >= 16 && (box.bottom <= window.innerHeight - 16 || (box.height > window.innerHeight - 32 && box.top <= 32));
  // Instant scrolling respects reduced motion. Move keyboard focus only if
  // its control would otherwise remain outside the resulting viewport.
  const card = output.closest?.<HTMLElement>('.password-row') ?? output;
  if (!visible) card.scrollIntoView({ behavior: 'instant', block: 'start', inline: 'nearest' });
  const focused = document.activeElement?.getBoundingClientRect();
  if (keyboard && focused && (focused.top < 0 || focused.bottom > window.innerHeight)) {
    card.focus({ preventScroll: true });
    return true;
  }
  return false;
}
function revealFieldError(): void {
  const active = document.activeElement as HTMLElement | null;
  if (!active || !policyInputIds.includes(active.id) || !active.getBoundingClientRect) return;
  const error = element(active.id + '-error');
  if (error.hidden || typeof window.innerHeight !== 'number') return;
  const control = active.getBoundingClientRect(), box = error.getBoundingClientRect();
  // Reveal the description only when both it and its focused control fit.
  if (box.bottom - control.top > window.innerHeight - 32) return;
  const delta = box.bottom > window.innerHeight - 16 ? box.bottom - window.innerHeight + 16
    : control.top < 16 ? control.top - 16 : 0;
  if (delta) {
    const dialog = document.getElementById('settings-disclosure') as HTMLDialogElement | null;
    if (dialog?.open) dialog.scrollBy({ top: delta, behavior: 'instant' });
    else window.scrollBy({ top: delta, behavior: 'instant' });
  }
}
function profilePanels(): void {
  for (const [id, selected] of [['readable-settings', 'readable'], ['strong-settings', 'strong-random'], ['custom-settings', 'custom-policy']]) {
    const panel = element<HTMLFieldSetElement>(id!);panel.hidden = profile.value !== selected;panel.disabled = panel.hidden;
  }
  const inline = document.getElementById('custom-policy-inline');
  if (inline) inline.hidden = profile.value !== 'custom-policy';
  const feedback = document.getElementById('policy-feedback');
  const destination = document.getElementById(profile.value === 'custom-policy' ? 'custom-feedback' : 'dialog-feedback');
  if (feedback && destination?.appendChild) destination.appendChild(feedback);
  // Modal profile selection must not leave inline controls behind an inert background.
  if (profile.value === 'custom-policy') closeSettings();
  element('readable-format').hidden = profile.value !== 'readable';
  element('word-metric').hidden = profile.value !== 'readable';
  element('profile-help').textContent = profile.value === 'readable' ? 'Three distinct dictionary words with numbers and symbols.'
    : profile.value === 'strong-random' ? 'Random characters. Every enabled category is required at least once.'
    : 'Printable ASCII with your explicit allowed categories, minimum counts and exclusions.';
}
function generatedEntry(context: ProfileOutput): PasswordEntry {
  const value = context.generate();
  if (!context.validate(value)) throw new Error('Generated password failed final validation.');
  return { value, context };
}
function summary(): void {
  resetFieldErrors();
  try {
    const selected = request();
    if (selected.profile !== 'readable') {
      const analysis = analyzePolicy(policyForProfile(selected));
      element('word-count').textContent = '—';
      element('entropy').textContent = analysis.kind === 'invalid' ? '—' : `${analysis.entropy.estimatedBitsText} bits`;
      element('strength-note').textContent = analysis.kind === 'eligible'
        ? analysis.entropy.description + ' Customer policies must be checked separately.'
        : policyMessages(analysis.errors);
      generate.disabled = analysis.kind !== 'eligible' || typeof globalThis.crypto?.getRandomValues !== 'function';
      if (analysis.kind !== 'eligible') fieldErrors(analysis.errors);
      return;
    }
    const s = selected.settings; assertSettings(s);
    const pool = eligibleWords(WORDS, s);
    element('word-count').textContent = pool.length.toLocaleString();
    const bits = entropyBits(pool.length, s.suffixLength);
    element('entropy').textContent = `${bits.toFixed(1)} bits`;
    const required = minimumSuffixLength(pool.length);
    const belowPolicy = !meetsEntropyPolicy(pool.length, s.suffixLength);
    element('strength-note').textContent = belowPolicy
      ? `Generation blocked: ${bits.toFixed(2)} bits is below the ${MIN_ENTROPY_BITS}-bit standard policy. Increase suffix length to at least ${required} characters for these ${pool.length} eligible words, or broaden the word range.`
      : `Meets the ${MIN_ENTROPY_BITS}-bit standard policy. Entropy alone does not guarantee security against offline attacks.`;
    generate.disabled = belowPolicy || typeof globalThis.crypto?.getRandomValues !== 'function';
    if (belowPolicy) fieldErrors([{ code: 'INSUFFICIENT_ENTROPY', field: 'policy', message: element('strength-note').textContent ?? '' }]);
  } catch (error) {
    element('entropy').textContent = '—';
    element('word-count').textContent = '—';
    element('strength-note').textContent = errorMessage(error);
    generate.disabled = true;
    fieldErrors(error instanceof PolicyGenerationError ? error.errors : [{ code: 'INVALID_POLICY', field: 'policy', message: errorMessage(error) }]);
  } finally { settingsSummary(); }
}
function passwordRow(entry: PasswordEntry, index: number): HTMLElement {
  const password = entry.value;
  const row = document.createElement('article'); row.className = 'password-row';
  row.tabIndex = -1;
  row.setAttribute('aria-label', `Generated password ${index + 1} of ${passwords.length}, ${entry.context.profile === 'readable' ? 'Readable' : entry.context.profile === 'strong-random' ? 'Strong Random' : 'Custom Policy'}, validated`);
  const top = document.createElement('div'); top.className = 'row-top';
  const info = document.createElement('small');
  const valid = entry.context.validate(password);
  if (!valid) throw new Error('Password display validation failed.');
  info.textContent = `${String(index + 1).padStart(2, '0')} / ${password.length} characters`;
  const copy = document.createElement('button'); copy.type = 'button'; copy.className = 'copy-password primary'; copy.textContent = count.value === '1' ? 'Copy Password' : 'Copy'; copy.setAttribute('aria-label', `Copy password ${index + 1}`);
  copy.addEventListener('click', () => { synchronizeSettings(); if (passwords[index] === entry) void copyText(password, `password ${index + 1}`, copy); });
  const regenerateButton = document.createElement('button'); regenerateButton.type = 'button';
  regenerateButton.className = 'regenerate'; regenerateButton.textContent = 'Regenerate';
  regenerateButton.setAttribute('aria-label', `Regenerate password ${index + 1}`);
  regenerateButton.addEventListener('click', () => { regeneratePassword(index, entry, row); });
  top.append(info, copy, regenerateButton);
  const text = document.createElement('div'); text.className = 'password';
  text.classList.toggle('literal', entry.context.profile !== 'readable');
  if (show.checked && entry.context.profile !== 'readable') text.textContent = password;
  else if (show.checked) password.split('.').forEach((part, i) => {
    const group = document.createElement('span'); group.className = 'password-part';
    const segment = document.createElement('span'); segment.className = 'segment'; segment.textContent = part; group.append(segment);
    if (i < 3) { const dot = document.createElement('span'); dot.className = 'dot'; dot.textContent = '.'; group.append(dot); }
    text.append(group);
  });
  else { text.textContent = '••••••••••••••••'; text.setAttribute('aria-label', `Password ${index + 1} hidden`); }
  row.append(top, text);
  if (entry.context.profile === 'readable') {
    const components = document.createElement('div'); components.className = 'component-copy';
    components.setAttribute('role', 'group'); components.setAttribute('aria-label', `Copy components of password ${index + 1}`);
    password.split('.').forEach((part, i) => {
      const label = i === 3 ? 'suffix' : `word ${i + 1}`;
      const button = document.createElement('button'); button.type = 'button';
      button.textContent = i === 3 ? 'Suffix' : `Word ${i + 1}`;
      button.setAttribute('aria-label', `Copy ${label} of password ${index + 1}`);
      button.addEventListener('click', () => { synchronizeSettings(); if (passwords[index] === entry) void copyText(part, `${label} of password ${index + 1}`, button); });
      components.append(button);
    });
    const disclosure = document.createElement('details'); disclosure.className = 'component-disclosure';
    const label = document.createElement('summary'); label.textContent = 'Copy a word or suffix';
    disclosure.append(label, components);
    row.append(disclosure);
  }
  const metrics = document.createElement('div'); metrics.className = 'row-metrics';
  const entropy = document.createElement('span'); entropy.textContent = 'Estimated entropy: ' + element('entropy').textContent;
  const validation = document.createElement('span'); validation.className = 'validation';
  validation.textContent = entry.context.profile === 'readable' ? '✓ Format valid · 64-bit minimum met' : '✓ Configured rules met · 64-bit minimum met';
  metrics.append(entropy, validation); row.append(metrics);
  if (entry.context.profile === 'readable') {
    const hint = document.createElement('p'); hint.className = 'password-hint';
    hint.textContent = 'Periods are literal password characters. No spaces.'; row.append(hint);
  }
  const spaces = [...password].filter(character => character === ' ').length;
  if (spaces && show.checked) {
    const note = document.createElement('p'); note.className = 'password-space-note';
    const edges = [password.startsWith(' ') ? 'Starts with a space.' : '', password.endsWith(' ') ? 'Ends with a space.' : ''].filter(Boolean);
    note.textContent = `Contains ${spaces} space${spaces === 1 ? '' : 's'}. ${edges.join(' ')}`.trim();
    row.append(note);
  }
  return row;
}
function regeneratePassword(index: number, previous: PasswordEntry, row: HTMLElement): void {
  synchronizeSettings();
  // Ignore actions belonging to a cleared or replaced card.
  if (passwords[index] !== previous) return;
  resetCopyFeedback();
  try {
    const context = prepareProfileOutput(request(), WORDS);
    const replacement = context.generate();
    if (!context.validate(replacement)) throw new Error('Replacement validation failed.');
    const next = { value: replacement, context };
    const nextRow = passwordRow(next, index);
    // Commit only after generation, validation and construction have succeeded.
    row.replaceWith(nextRow);
    passwords[index] = next; revision++;
    nextRow.querySelector<HTMLButtonElement>('.regenerate')?.focus({ preventScroll: true });
    status.textContent = `Password ${index + 1} regenerated and validated. Other passwords unchanged.`;
    ensureResultVisible(nextRow.querySelector<HTMLElement>('.password'));
  } catch {
    status.textContent = `Could not regenerate password ${index + 1}. Existing password preserved. Check settings and secure randomness.`;
  }
}
function render(): void {
  resetCopyFeedback();
  list.replaceChildren();
  list.classList.toggle('manual-mode', manual.checked);
  layoutSummary();
  passwords.forEach((entry, index) => { list.append(passwordRow(entry, index)); });
  if (!passwords.length) {
    const empty = document.createElement('div'); empty.className = 'empty';
    const heading = document.createElement('h3'); heading.textContent = 'A clear password starts here.';
    const note = document.createElement('p'); note.textContent = 'Choose your settings and generate. Every result is checked before it appears.';
    empty.append(heading, note); list.append(empty);
  }
  copyAll.disabled = !passwords.length; clearButton.disabled = !passwords.length;
}
function resetCopyFeedback(): void {
  copyAttempt++;
  // Labels contain no password data. Weak keys cannot retain cleared cards.
  for (const button of document.querySelectorAll?.<HTMLButtonElement>('button[data-copy-feedback]') ?? []) {
    const label = copyLabels.get(button);
    if (label) button.textContent = label;
    button.removeAttribute('data-copy-feedback');
  }
}
async function copyText(text: string, label: string, button: HTMLButtonElement): Promise<void> {
  resetCopyFeedback();
  const attempt = copyAttempt;
  const currentRevision = revision;
  if (!copyLabels.has(button)) copyLabels.set(button, button.textContent ?? 'Copy');
  button.textContent = 'Copying…'; button.setAttribute('data-copy-feedback', 'pending');
  const previousWrite = clipboardWrite;
  let release!: () => void;
  const thisWrite = new Promise<void>(resolve => { release = resolve; });
  clipboardWrite = thisWrite;
  try {
    // Native writes cannot be cancelled. Serialize them, skipping queued work
    // that became stale, so an older write cannot finish after a newer one.
    if (previousWrite) await previousWrite;
    if (revision !== currentRevision || attempt !== copyAttempt) return;
    if (!globalThis.isSecureContext || !navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
    await navigator.clipboard.writeText(text);
    if (revision === currentRevision && attempt === copyAttempt) {
      button.textContent = 'Copied'; button.setAttribute('data-copy-feedback', 'success');
      status.textContent = `Copied. ${label[0]?.toUpperCase()}${label.slice(1)} copied. Your operating system may retain clipboard history.`;
    }
  } catch {
    if (revision === currentRevision && attempt === copyAttempt) {
      button.textContent = 'Copy failed'; button.setAttribute('data-copy-feedback', 'failure');
      status.textContent = 'Clipboard unavailable. Show the password and select it to copy, or use large-text mode to type it.';
    }
  } finally {
    release();
    if (clipboardWrite === thisWrite) clipboardWrite = undefined;
  }
}
function clear(): void { passwords = []; revision++; render(); }
// Trusted keyboard events distinguish real activation from requestSubmit/click.
for (const boundary of [form, element('custom-settings')]) {
  boundary.addEventListener('keydown', event => {
    keyboardSubmission = event.isTrusted && (event.key === 'Enter' || (event.key === ' ' && event.target === generate));
  });
  boundary.addEventListener('keyup', () => { keyboardSubmission = false; });
  boundary.addEventListener('pointerdown', () => { keyboardSubmission = false; });
}
generate.addEventListener('click', event => { keyboardSubmission = event.isTrusted && event.detail === 0; });
form.addEventListener('submit', event => {
  event.preventDefault();
  const keyboard = keyboardSubmission && event.isTrusted;
  keyboardSubmission = false;
  resetCopyFeedback();
  try {
    synchronizeSettings();summary();
    const quantity = Number(count.value);
    if (![1, 5, 10, 20].includes(quantity)) throw new Error('Invalid password count.');
    const context = prepareProfileOutput(request(), WORDS);
    const next = Array.from({ length: quantity }, () => generatedEntry(context));
    passwords = next; revision++; render();
    closeSettings();
    // Focus announces the named result; otherwise use the existing live status.
    status.textContent = ensureResultVisible(undefined, keyboard) ? ''
      : `${quantity} password${quantity === 1 ? '' : 's'} generated and validated on your device.`;
  } catch (error) {
    // synchronizeSettings already invalidates old policies. A failure with the
    // same settings must not discard valid results or disturb their selection.
    summary();
    status.textContent = element('policy-status').textContent ? '' : passwords.length
      ? `Could not generate new passwords. Existing password${passwords.length === 1 ? '' : 's'} preserved. Try again or check secure browser randomness.`
      : typeof globalThis.crypto?.getRandomValues !== 'function' ? 'Secure browser randomness is unavailable. Use HTTPS or localhost in a supported browser.'
      : error instanceof PolicyGenerationError ? errorMessage(error) : 'Could not generate passwords. Try again or reload the page.';
  }
});
function settingsChanged(): void {
  clear(); summary();
  try { observedSettings = Object.freeze(settingsValues()); } catch { observedSettings = []; }
  status.textContent = element('policy-status').textContent ? '' : 'Settings changed. Generate fresh passwords.';
  revealFieldError();
}
profile.addEventListener('change', () => { profilePanels(); settingsChanged(); });
for (const input of [suffix, min, max, count]) input.addEventListener('input', () => { if (input === count || profile.value === 'readable') settingsChanged(); });
count.addEventListener('change', settingsChanged);
for (const [prefix, selected] of [['strong', 'strong-random'], ['custom', 'custom-policy']]) {
  const ids = [prefix + '-length', prefix + '-exclusions', prefix + '-ambiguous', ...CATEGORIES.map(id => prefix + '-' + id)];
  if (prefix === 'custom') ids.push('custom-symbol-list', ...CATEGORIES.map(id => 'custom-min-' + id));
  for (const id of ids) {
    const input = element<HTMLInputElement>(id);
    for (const event of ['input', 'change']) input.addEventListener(event, () => { if (profile.value === selected) settingsChanged(); });
  }
}
form.addEventListener('focusin', synchronizeSettings);
element('custom-settings').addEventListener('focusin', synchronizeSettings);
// Native substring copying also crosses the settings boundary. Cancel only a
// stale copy; ordinary selection and Ctrl+C continue to use browser behavior.
document.addEventListener?.('copy', event => {
  // Capture selection before synchronization removes stale cards. Textarea
  // selections are independent of document ranges and must remain copyable.
  const target = event.target as HTMLElement | null;
  const editor = target?.closest?.('input, textarea, [contenteditable="true"]');
  const selection = editor ? null : document.getSelection?.();
  let passwordSelected = false;
  if (selection && !selection.isCollapsed) {
    for (let i = 0; i < selection.rangeCount; i++) {
      const range = selection.getRangeAt(i);
      for (const text of list.querySelectorAll('.password')) {
        if (range.intersectsNode(text)) passwordSelected = true;
      }
    }
  }
  if (synchronizeSettings() && passwordSelected) event.preventDefault();
}, true);
window.addEventListener('focus', synchronizeSettings);
show.addEventListener('change', () => { synchronizeSettings();render(); }); manual.addEventListener('change', () => { synchronizeSettings();render(); });
copyAll.addEventListener('click', () => { synchronizeSettings(); if (passwords.length) void copyText(passwords.map(entry => entry.value).join('\n'), 'all passwords', copyAll); });
clearButton.addEventListener('click', () => { clear(); status.textContent = 'Passwords cleared from this page. Previously copied text remains on the clipboard.'; });
// Avoid restoring generated values from back/forward page snapshots.
window.addEventListener('pagehide', clear);
window.addEventListener('pageshow', event => { if (event.persisted) { clear(); status.textContent = 'Ready. Generate fresh passwords.'; } });
profilePanels();
summary();
observedSettings = Object.freeze(settingsValues());
status.textContent = typeof globalThis.crypto?.getRandomValues === 'function' ? 'Ready. Passwords stay in this page until cleared or reloaded.' : 'Secure randomness unavailable. Use a modern browser over HTTPS or localhost.';

// Presentation only. Native modal semantics make background controls inert.
function openSettings(): void {
  const dialog = document.getElementById('settings-disclosure') as HTMLDialogElement | null;
  if (dialog && !dialog.open && typeof dialog.showModal === 'function') dialog.showModal();
}
function closeSettings(): void {
  const dialog = document.getElementById('settings-disclosure') as HTMLDialogElement | null;
  if (dialog?.open && typeof dialog.close === 'function') {
    dialog.close(); element('settings-summary').focus({ preventScroll: true });
  }
}
function layoutSummary(): void {
  const batch = Number(count.value) > 1;
  list.classList.toggle('focus', !batch); list.classList.toggle('batch', batch);
  document.body?.classList.toggle('is-batch', batch);
  const title = document.getElementById('results-title');
  if (title) title.textContent = batch ? count.value + ' passwords' : 'Your password';
  copyAll.hidden = !batch;
  clearButton.textContent = batch ? 'Clear batch' : 'Clear';
  const hint = document.getElementById('batch-hint');
  if (hint) { hint.hidden = !batch || profile.value !== 'readable'; }
  const note = document.getElementById('mode-note');
  if (note) note.textContent = batch ? 'All results. One sheet.' : 'One password. A clear view.';
}
function settingsSummary(): void {
  const overview = document.getElementById('active-settings');
  if (overview) {
    try {
      const selected = request();
      const name = selected.profile === 'readable' ? 'Readable' : selected.profile === 'strong-random' ? 'Strong Random' : 'Custom Policy';
      if (element('policy-status').textContent) overview.textContent = `${name} · Review the marked settings.`;
      else if (selected.profile === 'readable') {
        const s = selected.settings;
        overview.textContent = `Readable · 3 distinct words, ${s.minWordLength}–${s.maxWordLength} letters each · ${s.suffixLength}-character suffix`;
      } else {
        const s = selected.settings!;
        const labels = { uppercase: 'uppercase', lowercase: 'lowercase', digits: 'numbers', symbols: 'symbols' };
        const categories = CATEGORIES.filter(id => s.allowed[id]).map(id => selected.profile === 'custom-policy'
          ? `${labels[id]} (minimum ${selected.settings.minimumCounts[id]})` : labels[id]);
        const exclusions = new Set(s.excludedCharacters).size;
        const symbolCount = selected.profile === 'custom-policy'
          ? new Set([...selected.settings.permittedSymbols].filter(character => !s.excludedCharacters.includes(character))).size : 0;
        overview.textContent = `${name} · ${s.length} characters · ${categories.join(', ')}${s.excludeAmbiguous ? ' · Ambiguous characters excluded' : ''}${exclusions ? ` · ${exclusions} additional exclusion${exclusions === 1 ? '' : 's'}` : ''}${selected.profile === 'custom-policy' && s.allowed.symbols ? ` · ${symbolCount} allowed symbol${symbolCount === 1 ? '' : 's'}` : ''}`;
      }
    } catch { overview.textContent = 'Review the marked settings.'; }
  }
  const warning = document.getElementById('settings-summary-error');
  if (warning) {
    warning.hidden = !element('policy-status').textContent;
    warning.textContent = warning.hidden ? '' : profile.value === 'custom-policy'
      ? 'Generation blocked. Review the marked Custom Policy fields below.'
      : 'Generation blocked. Open Settings to review the marked fields.';
  }
  const mirror = document.getElementById('dialog-count') as HTMLSelectElement | null;
  if (mirror) mirror.value = count.value;
  for (const id of ['batch-generate', 'settings-generate']) {
    const button = document.getElementById(id) as HTMLButtonElement | null;
    if (button) { button.disabled = generate.disabled; if (id === 'batch-generate') button.hidden = count.value === '1'; }
  }
  document.querySelectorAll?.<HTMLButtonElement>('[data-profile]').forEach(button => {
    button.setAttribute('aria-pressed', String(button.dataset.profile === profile.value));
  });
  layoutSummary();
}
element('settings-summary').addEventListener('click', openSettings);
for (const id of ['settings-close', 'settings-done']) element(id).addEventListener('click', closeSettings);
element('settings-disclosure').addEventListener('keydown', event => {
  if (event.key !== 'Tab') return;
  const dialog = element<HTMLDialogElement>('settings-disclosure');
  const controls = [...dialog.querySelectorAll<HTMLElement>('button, select, input, textarea, summary, [tabindex="0"]')]
    .filter(node => !node.matches(':disabled') && node.getClientRects().length > 0);
  const first = controls[0], last = controls.at(-1);
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
});
element('settings-disclosure').addEventListener('cancel', event => { event.preventDefault(); closeSettings(); });
element<HTMLSelectElement>('dialog-count').addEventListener('change', event => {
  count.value = (event.target as HTMLSelectElement).value; settingsChanged();
});
document.querySelectorAll?.<HTMLButtonElement>('[data-profile]').forEach(button => {
  button.addEventListener('click', () => {
    profile.value = button.dataset.profile!; profilePanels(); settingsChanged();
  });
});
for (const id of ['batch-generate', 'settings-generate']) element(id).addEventListener('click', event => {
  keyboardSubmission = event.isTrusted && event.detail === 0;
});
settingsSummary();
