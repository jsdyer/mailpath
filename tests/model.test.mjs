import test from 'node:test';
import assert from 'node:assert/strict';
import { parseMail } from '../web/model.mjs';
import { SAMPLE } from './mail-fixture.mjs';

test('unfolds fields and returns oldest-to-newest relay claims', () => {
  const data = parseMail(SAMPLE);
  assert.deepEqual(data.hops.map((hop) => hop.receiver), ['outbound.sender.example', 'relay.example.net', 'inbox.example.com']);
  assert.equal(data.hops[1].ip, '2001:db8::28');
  assert.equal(data.duration, 18000);
  assert.equal(data.hops[2].delay, 8000);
  assert.deepEqual(data.auth.map((check) => check.method), ['spf', 'dkim', 'dmarc']);
  assert.ok(data.auth.every((check) => check.server === 'inbox.example.com' && check.domain === 'sender.example'));
  assert.doesNotMatch(JSON.stringify(data), /bounce@|someone@|Synthetic relay trace|synthetic-not-a-signature/);
});

test('handles comments and ARC authserv IDs without leaking identity or body', () => {
  const data = parseMail('ARC-Authentication-Results: i=2; mx.example; spf=softfail (fake; dkim=pass) smtp.mailfrom="<me@example.org>"\r\nReceived-SPF: pass (local test) receiver=mx.example; envelope-from=alice@elsewhere.example\r\n\r\nAuthentication-Results: body.example; spf=pass');
  assert.deepEqual(data.auth.map((a) => [a.method, a.result, a.server, a.domain]), [
    ['spf', 'softfail', 'mx.example', 'example.org'],
    ['spf', 'pass', 'mx.example', 'elsewhere.example'],
  ]);
  assert.doesNotMatch(JSON.stringify(data), /me@|alice@|body.example/);
});

test('flags reverse times and missing trace timezone', () => {
  const data = parseMail('Received: from edge.example by inbox.example; 16 Nov 2026 10:00:00 +0000\nReceived: from sender.example by edge.example; 16 Nov 2026 11:00:00 +0000\nReceived: from unknown.example by sender.example; 16 Nov 2026 10:00:00');
  assert.equal(data.hops[2].delay, -3600000);
  assert.equal(data.hops[0].timestamp, null);
  assert.equal(data.warnings.length, 2);
  assert.throws(() => parseMail('Random text'), /No message header fields/);
});

test('extracts DKIM key lookup details without retaining signature material', () => {
  const data = parseMail('DKIM-Signature: v=1; d=sender.example;\r\n s=mail2026; b=PRIVATE_SIGNATURE\r\nDKIM-Signature: v=1; d=other.example; s=first; s=second; b=SECRET\r\n\r\nbody');
  assert.deepEqual(data.signingKeys, [
    { domain: 'sender.example', selector: 'mail2026' },
    { domain: 'other.example', selector: null },
  ]);
  assert.doesNotMatch(JSON.stringify(data), /PRIVATE_SIGNATURE|SECRET|body/);
});
