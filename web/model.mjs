const MAX_TEXT = 500000;
const FIELD = /^([!-9;-~]{1,80}):[ \t]*(.*)$/;
const METHODS = new Set(['spf', 'dkim', 'dmarc', 'arc', 'iprev', 'smtp.auth', 'bimi', 'compauth']);
const RESULTS = new Set(['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror', 'policy', 'hardfail', 'nxdomain', 'bestguesspass', 'unknown']);

function splitProtocol(input) {
  const result = [''];
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (const char of input) {
    if (escaped) {
      if (!depth) result[result.length - 1] += char;
      escaped = false;
      continue;
    }
    if (char === '\\' && (quoted || depth)) { escaped = true; continue; }
    if (char === '(' && !quoted) {
      if (!depth) result[result.length - 1] += ' ';
      depth++;
      continue;
    }
    if (char === ')' && depth) { depth--; continue; }
    if (depth) continue;
    if (char === '"') quoted = !quoted;
    if (char === ';' && !quoted) result.push('');
    else result[result.length - 1] += char;
  }
  return result;
}

function address(token) {
  const value = String(token || '').replace(/^\[|\]$/g, '').replace(/^IPv6:/i, '');
  const octets = value.split('.');
  if (octets.length === 4 && octets.every((item) => /^\d{1,3}$/.test(item) && Number(item) < 256)) return octets.map(Number).join('.');
  if (value.includes(':') && /^[a-f0-9:.]+$/i.test(value)) {
    try { return new URL(`http://[${value}]/`).hostname.slice(1, -1); } catch { return null; }
  }
  return null;
}

function host(token) {
  const value = String(token || '').trim().replace(/^"|"$/g, '').replace(/\.$/, '').toLowerCase();
  const ip = address(value);
  if (ip) return ip;
  if (value.length > 253 || !/^[a-z\d_-]+(?:\.[a-z\d_-]+)*$/.test(value)) return null;
  return value;
}

function date(value) {
  const trimmed = value.trim();
  if (!/(?:[+-]\d{4}|UT|UTC|GMT|[ECMP][SD]T|Z)$/i.test(trimmed)) return null;
  const time = Date.parse(trimmed);
  return Number.isFinite(time) ? time : null;
}

function received(value) {
  const [trace, ...dates] = splitProtocol(value);
  const from = /(?:^|\s)from\s+(\[[^\]]{1,64}\]|[^\s]+)/i.exec(trace);
  const by = /(?:^|\s)by\s+(\[[^\]]{1,64}\]|[^\s]+)/i.exec(trace);
  const originalTrace = value.split(';', 1)[0];
  const originalFrom = /\bfrom\s+(.+?)(?=\s+by\s+|$)/i.exec(originalTrace)?.[1] ?? '';
  let ip = address(from?.[1]);
  if (!ip) {
    const candidates = [...originalFrom.matchAll(/\[([^\]]{1,64})\]/g)];
    ip = candidates.map((match) => address(match[1])).find(Boolean) ?? null;
  }
  const transport = /(?:^|\s)with\s+([a-z0-9-]{1,16})/i.exec(trace)?.[1]?.toUpperCase();
  return {
    sender: host(from?.[1]), receiver: host(by?.[1]), ip,
    transport: transport && /^(?:SMTP|SMTPS|ESMTP|ESMTPS|ESMTPA|ESMTPSA|LMTP|LMTPS|LMTPA|LMTPSA|HTTP|HTTPS|MAPI|LOCAL)$/.test(transport) ? transport : null,
    timestamp: dates.length ? date(dates[dates.length - 1]) : null,
  };
}

function authDomain(value) {
  const matches = /\b(header\.(?:d|from)|smtp\.(?:mailfrom|helo))\s*=\s*(?:"([^"]+)"|([^\s;]+))/i.exec(value);
  const token = matches?.[2] ?? matches?.[3] ?? '';
  const domain = token.replace(/^[<]|[>]$/g, '').split('@').pop();
  return host(domain);
}

function authResults(value, field) {
  const parts = splitProtocol(value);
  if (field === 'arc-authentication-results' && /^\s*i\s*=\s*\d+\s*$/i.test(parts[0])) parts.shift();
  const server = host(parts.shift()?.trim().split(/\s+/, 1)[0]);
  return parts.flatMap((part) => {
    const match = /^\s*([a-z.]+)(?:\/\d+)?\s*=\s*([a-z-]+)/i.exec(part);
    if (!match) return [];
    const method = match[1].toLowerCase();
    const result = match[2].toLowerCase();
    return METHODS.has(method) && RESULTS.has(result) ? [{ method, result, server, domain: authDomain(part), field }] : [];
  });
}

function spfResult(value) {
  const clean = splitProtocol(value).join(';');
  const result = clean.trim().split(/\s+/, 1)[0].toLowerCase();
  if (!RESULTS.has(result)) return [];
  const serverMatch = /\breceiver\s*=\s*([^; \t]+)/i.exec(clean);
  const domainMatch = /\benvelope-from\s*=\s*([^; \t]+)/i.exec(clean);
  const domain = domainMatch?.[1]?.replace(/^["<]|[">]$/g, '').split('@').pop();
  return [{ method: 'spf', result, server: host(serverMatch?.[1]), domain: host(domain), field: 'received-spf' }];
}

function signatureDetails(value) {
  const tags = new Map();
  const duplicates = new Set();
  for (const part of splitProtocol(value)) {
    const match = /^\s*([a-z][a-z0-9_]*)\s*=\s*(.*?)\s*$/i.exec(part);
    if (!match) continue;
    const name = match[1].toLowerCase();
    if (tags.has(name)) duplicates.add(name);
    tags.set(name, match[2]);
  }
  return {
    domain: duplicates.has('d') ? null : host(tags.get('d')),
    selector: duplicates.has('s') ? null : host(tags.get('s')),
  };
}

export function parseMail(input) {
  if (typeof input !== 'string' || input.length > MAX_TEXT) throw new Error('Open up to 500,000 characters of message headers.');
  const rawLines = input.replace(/^\uFEFF/, '').split(/\r\n|\r|\n/);
  const fields = [];
  for (const line of rawLines) {
    if (!line.trim()) { if (fields.length) break; continue; }
    if (/^[ \t]/.test(line) && fields.length) {
      fields[fields.length - 1].value = (fields[fields.length - 1].value + ' ' + line.trim()).slice(0, 15000);
      continue;
    }
    const field = FIELD.exec(line);
    if (!field) { if (fields.length) break; continue; }
    if (fields.length === 900) throw new Error('More than 900 header fields. Copy only the message header section.');
    fields.push({ name: field[1].toLowerCase(), value: field[2].slice(0, 15000) });
  }
  const hops = fields.filter((field) => field.name === 'received').map((field) => received(field.value)).reverse();
  const auth = fields.flatMap(({ name, value }) => {
    if (name === 'authentication-results' || name === 'arc-authentication-results') return authResults(value, name);
    if (name === 'received-spf') return spfResult(value);
    return [];
  }).slice(0, 250);
  const signatureFields = fields.filter((field) => field.name === 'dkim-signature');
  const signatures = signatureFields.length;
  const signingKeys = signatureFields.map((field) => signatureDetails(field.value));
  const warnings = [];
  for (const [index, hop] of hops.entries()) {
    const previous = hops[index - 1];
    hop.delay = index && hop.timestamp !== null && previous.timestamp !== null ? hop.timestamp - previous.timestamp : null;
    if (hop.timestamp === null) warnings.push(`Hop ${index + 1} has no recognized time with a timezone.`);
    if (hop.delay !== null && hop.delay < 0) warnings.push(`Hop ${index + 1} has an earlier timestamp than the prior hop. Compare clocks and source headers.`);
  }
  if (auth.some((check) => check.result === 'fail' || check.result === 'permerror' || check.result === 'temperror')) {
    warnings.push('At least one reporting header contains an authentication failure or error. Compare the reporting server and domain before drawing a conclusion.');
  }
  if (!fields.length) throw new Error('No message header fields found. Open the message source and copy the header section.');
  if (!hops.length && !auth.length && !signatures) warnings.push('The message has no recognized relay or authentication results in the inspected header section.');
  const first = hops[0]?.timestamp ?? null;
  const final = hops[hops.length - 1]?.timestamp ?? null;
  return {
    hops, auth, signatures, signingKeys, warnings,
    duration: hops.length > 1 && first !== null && final !== null && final >= first ? final - first : null,
  };
}
