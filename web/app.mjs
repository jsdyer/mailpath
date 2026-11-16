import { $, announce, downloadJSON, el, installTheme, stat, table, tag, wireDrop } from './ui.mjs';
import { parseMail } from './model.mjs';
import { SAMPLE } from './sample.mjs';

let report = null;
let generation = 0;

function span(value) {
  if (value === null) return 'Unavailable';
  const seconds = Math.abs(value) / 1000;
  const prefix = value < 0 ? '−' : '';
  if (seconds < 60) return `${prefix}${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${prefix}${minutes} min ${Math.floor(seconds % 60)} s`;
  return `${prefix}${Math.floor(minutes / 60)} hr ${minutes % 60} min`;
}

function utc(value) {
  return value === null ? 'Time unavailable' : new Date(value).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

function show(value, fromFile) {
  report = value;
  if (fromFile) $('paste').value = '';
  $('stats').replaceChildren(stat('Reported hops', value.hops.length), stat('Auth results', value.auth.length),
    stat('DKIM signature fields', value.signatures), stat('First to last reported time', span(value.duration)));
  $('hops').replaceChildren(...value.hops.map((hop, index) => {
    const item = el('li');
    item.append(el('h3', `${hop.sender ?? 'Sender unavailable'} → ${hop.receiver ?? 'Receiver unavailable'}`));
    item.append(el('p', [hop.ip && `Reported sending IP ${hop.ip}`, hop.transport, utc(hop.timestamp)].filter(Boolean).join(' · '), 'mono'));
    if (index && hop.delay !== null) item.append(tag(hop.delay < 0 ? `Timestamp reversal ${span(hop.delay)}` : `${span(hop.delay)} since previous hop`, hop.delay < 0 ? 'review' : undefined));
    return item;
  }));
  $('no-hops').hidden = value.hops.length > 0;
  table($('auth'), value.auth.map((item) => [
    item.method.toUpperCase(),
    tag(item.result, /fail|error/.test(item.result) ? 'review' : undefined),
    item.server ?? 'Unavailable', item.domain ?? 'Unavailable', el('code', item.field),
  ]), 5, 'No recognized authentication results found.');
  table($('signing-keys'), value.signingKeys.map(({ domain, selector }) => [
    domain ?? 'Unavailable', selector ?? 'Unavailable',
    domain && selector ? `${selector}._domainkey.${domain}` : 'Unavailable',
  ]), 3, 'No DKIM signature fields found.');
  $('warnings').replaceChildren(...value.warnings.map((warning) => el('li', warning)));
  $('notes').hidden = value.warnings.length === 0;
  $('report').hidden = false;
  announce('Analysis ready. The timeline shows claims from the message headers.');
}

function clear() {
  generation++;
  report = null;
  $('report').hidden = true;
  $('stats').replaceChildren();
  $('hops').replaceChildren();
  $('auth').replaceChildren();
  $('signing-keys').replaceChildren();
  $('warnings').replaceChildren();
  $('paste').value = '';
  announce('Paste a header block, open message source, or try the example.');
}

function analyse() {
  generation++;
  try { show(parseMail($('paste').value), false); }
  catch (error) { announce(error.message, true); }
}

async function open(file) {
  const current = ++generation;
  try {
    announce('Reading the initial message source locally.');
    const limit = 500000;
    const prefix = await file.slice(0, limit).text();
    if (current !== generation) return;
    if (file.size > limit && !/\r\n\r\n|\n\n|\r\r/.test(prefix)) throw new Error('The message header block may exceed the 500 KB file prefix limit.');
    show(parseMail(prefix), true);
  } catch (error) {
    if (current === generation) announce(error.message, true);
  }
}

$('analyse').addEventListener('click', analyse);
$('sample').addEventListener('click', () => { $('paste').value = SAMPLE; analyse(); });
$('clear').addEventListener('click', clear);
$('choose').addEventListener('click', () => $('file').click());
$('export').addEventListener('click', () => { if (report) downloadJSON(report, 'mail-path-report.json'); });
wireDrop($('input'), $('file'), open);
installTheme();
