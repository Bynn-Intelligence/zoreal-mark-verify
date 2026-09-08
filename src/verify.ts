import { verifyAppended } from './appended.js';
import { verifyAppendedNoId } from './appended-noid.js';
import { concat, fromBase64Url, fromUtf8, sha256, toBase64Url, toHex, utf8 } from './bytes.js';
import { canonicalText, textHash } from './canonical.js';
import { verifyDeviceSignature } from './device.js';
import { isValidId, type Marker } from './format.js';
import { jcsHash } from './jcs.js';
import { jwsClaims, parseCompactJws, signingInput } from './jws.js';
import { MARK_AUDIENCE, verifyPresence } from './presence.js';
import { OID, PRODUCTION_ANCHORS, type TrustAnchors } from './roots.js';
import { checkStatusList } from './statuslist.js';
import { verifyTimestamp, type TimestampResult } from './timestamp.js';
import type { Binding, FetchResult, Grade, MarkRecord, Payload, PresenceClaims, StepResult, Verdict, VerifyResult } from './types.js';
import { normaliseUrl, siteOf } from './url.js';
import { EKU } from './x509/cert.js';
import { verifyJose } from './x509/verify.js';
import { confirmPairing, validateChain, type ValidatedChain } from './x509/chain.js';

export interface VerifyInput {
  marker: Marker;
  /** The text between the markers, as found on the page. */
  text: string;
  id: string;
}

export interface VerifyOptions {
  fetchRecord: (id: string) => Promise<FetchResult>;
  /** Defaults to the production anchors. Tests pass their own. */
  anchors?: TrustAnchors;
  now?: () => Date;
  /**
   * The URL of the page the text was found on. `undefined` when the verifier
   * cannot know it (a shared text on a phone); then a bound record renders as
   * verified for its own page rather than here.
   */
  pageUrl?: string;
  /** For an email binding: the message's From and its To plus Cc, as shown. */
  email?: { from: string; recipients: string[] };
}

class Fail extends Error {
  constructor(public step: number, message: string, public verdict: Verdict = 'not_verified') {
    super(message);
  }
}

const STEP_NAMES: Record<number, string> = {
  1: 'markers and id', 2: 'fetch the record', 3: 'classical chain', 4: 'post-quantum chain', 5: 'revocation',
  6: 'key usage', 7: 'presence required', 8: 'presence signatures', 9: 'presence bindings', 10: 'presence grade',
  11: 'device signature', 12: 'timestamp', 13: 'text hash', 14: 'binding', 15: 'withdrawal', 16: 'delegation',
  17: 'relations', 18: 'appended events',
};

/**
 * Verifies one Mark, running every step in order and failing closed. The
 * result carries the verdict, the step that failed when one did, and what a
 * hover card shows. Steps are reported in the order the specification lists
 * them; internally the timestamp is verified first, because steps 3 to 11 are
 * judged as of the confirmed time and that time has to be established before
 * it can be used.
 */
export async function verifyMark(input: VerifyInput, opts: VerifyOptions): Promise<VerifyResult> {
  const anchors = opts.anchors ?? PRODUCTION_ANCHORS;
  const now = opts.now ?? (() => new Date());
  const steps: StepResult[] = [];
  const ok = (step: number, detail?: string): void => { steps.push({ step, name: STEP_NAMES[step]!, ok: true, detail }); };
  const result: VerifyResult = { verdict: 'not_verified', steps };

  try {
    // 1
    if (!isValidId(input.id)) throw new Fail(1, 'no signature found: the id is not 24 Crockford base32 characters', 'no_signature');
    ok(1);

    // 2
    const fetched = await opts.fetchRecord(input.id);
    if (fetched.status === 'unavailable') throw new Fail(2, `cannot verify now: ${fetched.reason}`, 'cannot_verify_now');
    if (fetched.status === 'not_found') throw new Fail(2, 'no record exists for this id');
    const record = asRecord(fetched.record, input.id);
    result.record = record;
    ok(2);

    const payload = record.payload;
    result.identity = payload.identity;
    result.subject = payload.subject;
    result.site = payload.data.site;
    result.binding = payload.data.binding;
    result.signedUrl = payload.data.url;
    result.assurance = record.assurance;

    // Establish the time everything else is judged at.
    const ts = await verifyTimestamp(record, { anchors: anchors.timestamping });
    const asOf = ts.status === 'confirmed' ? ts.genTime : now();
    const delegated = record.presence && isDelegated(record);

    // 3, 4
    let classical: ValidatedChain;
    let postQuantum: ValidatedChain;
    try {
      classical = await validateChain(record.signature.certificate_chain, { anchors: anchors.classical, rootCertificates: anchors.rootCertificates, asOf, family: 'classical' });
    } catch (e) { throw new Fail(3, msg(e)); }
    ok(3, classical.root.subject);
    try {
      postQuantum = await validateChain(record.signature.paired_chain, { anchors: anchors.postQuantum, rootCertificates: anchors.rootCertificates, asOf, family: 'post_quantum' });
      confirmPairing(classical, postQuantum, { sameLeafKey: true });
    } catch (e) { throw new Fail(4, msg(e)); }
    ok(4, postQuantum.root.subject);
    const leaf = classical.leaf;

    // 5
    try {
      for (const [chain, jwt, label] of [[classical, record.signature.revocation?.classical, 'classical'], [postQuantum, record.signature.revocation?.post_quantum, 'post-quantum']] as const) {
        const slot = chain.leaf.zoreal.get(OID.statusList) as { idx?: unknown; uri?: unknown } | undefined;
        if (typeof slot?.idx !== 'number' || typeof slot?.uri !== 'string') throw new Error(`the ${label} certificate names no status list slot`);
        if (typeof jwt !== 'string') throw new Error(`the record carries no ${label} status list`);
        const status = await checkStatusList(jwt, chain.issuer, slot.idx, slot.uri, asOf);
        if (status.value !== 0) throw new Error(`the ${label} certificate was revoked (status ${status.value}) at the time of signing`);
      }
    } catch (e) { throw new Fail(5, msg(e)); }
    ok(5);

    // 6
    if (!leaf.keyUsage?.contentCommitment) throw new Fail(6, 'the certificate is not a content-commitment certificate');
    if (leaf.keyUsage.digitalSignature) throw new Fail(6, 'the certificate mixes contentCommitment with digitalSignature');
    if (!leaf.extendedKeyUsage?.includes(EKU.documentSigning)) throw new Fail(6, 'the certificate lacks the documentSigning key purpose');
    if (postQuantum.leaf.keyUsage && !postQuantum.leaf.keyUsage.contentCommitment) throw new Fail(6, 'the post-quantum certificate is not a content-commitment certificate');
    ok(6);

    // 7
    if (!leaf.zoreal.has(OID.presenceRequired)) throw new Fail(7, 'the certificate does not carry zoreal-presence-required');
    if (!record.presence) throw new Fail(7, 'no presence attestation accompanies the signature');
    ok(7);

    // Payload shape and consistency, before anything is verified against it.
    checkPayload(payload, record, input.marker, delegated);

    // 8, 9, 10 (and, for a delegated record, the human's attestation over the delegation)
    let claims: PresenceClaims;
    let deviceSigBytes: Uint8Array;
    let delegation: { agentName: string; humanSubject: string; agentJwk: JsonWebKey; order: string } | undefined;
    if (delegated) {
      const d = record.delegation!;
      const statement = parseCompactJws(d.statement);
      const stSig = statement.signatures[0]!;
      if (stSig.header.alg !== 'ES256') throw new Fail(16, `delegation statement is signed with ${stSig.header.alg}`);
      const stClaims = jwsClaims<DelegationClaims>(statement);
      deviceSigBytes = stSig.signature;
      delegation = { agentName: d.agent_name, humanSubject: d.human_subject, agentJwk: stClaims.agent_public_key, order: stClaims.order };
      try {
        const p = await verifyPresence(record.presence, { anchors, asOf, holderLeaf: leaf, deviceSignature: stSig.signature, order: stClaims.order, audience: MARK_AUDIENCE, allowedGrades: ['recent', 'live'] });
        claims = p.claims;
      } catch (e) { throw new Fail(presenceStep(e), msg(e)); }
      ok(8); ok(9); ok(10, `${claims.zoreal.grade} at delegation`);
      // The statement itself, under the human's key.
      if (!(await verifyJose(leaf, 'ES256', signingInput(stSig.protectedB64, statement.payloadB64), stSig.signature))) {
        throw new Fail(16, 'the delegation statement is not signed by the human named');
      }
    } else {
      try {
        deviceSigBytes = fromBase64Url(record.signature.device);
        const p = await verifyPresence(record.presence, { anchors, asOf, holderLeaf: leaf, deviceSignature: deviceSigBytes, order: payload.order, audience: MARK_AUDIENCE, allowedGrades: ['recent', 'live'] });
        claims = p.claims;
      } catch (e) { throw new Fail(presenceStep(e), msg(e)); }
      ok(8); ok(9); ok(10, claims.zoreal.grade);
    }
    result.grade = delegated ? 'delegated' : claims.zoreal.grade;
    result.claims = attachedClaims(claims);

    // 11
    if (delegated) {
      try {
        await verifyAgentSignature(payload, record.signature.device, delegation!.agentJwk, leaf.der);
      } catch (e) { throw new Fail(11, msg(e)); }
    } else {
      try { await verifyDeviceSignature(payload, record.signature.device, leaf); } catch (e) { throw new Fail(11, msg(e)); }
    }
    ok(11);

    // 12
    result.time = timeOf(ts, record);
    ok(12, result.time.status === 'confirmed' ? 'confirmed' : `unconfirmed: ${result.time.detail ?? 'pending'}`);

    // 13
    if (payload.visible.canonical !== 'mark-text-v1') throw new Fail(13, `unsupported canonicalisation ${payload.visible.canonical}`);
    const hash = await textHash(input.text);
    if (hash !== payload.visible.hash || hash !== payload.data.hash) throw new Fail(13, 'not verified: the text was altered');
    ok(13);

    // 14
    let verdict: Verdict;
    const binding = payload.data.binding;
    if (binding === 'page' || binding === 'channel') {
      if (payload.data.url === null) throw new Fail(14, 'a page binding without a URL');
      const signedFor = normaliseUrl(payload.data.url);
      if (signedFor !== payload.data.url) throw new Fail(14, 'the signed URL is not in normal form');
      if (opts.pageUrl === undefined) {
        verdict = 'verified_other_page';
        ok(14, 'page unknown to the verifier');
      } else {
        const here = safeNormalise(opts.pageUrl);
        if (here === signedFor) { verdict = binding === 'page' ? 'verified_here' : 'verified_in_channel'; ok(14, 'URL matches'); }
        else { verdict = 'verified_other_page'; ok(14, `signed for ${signedFor}`); }
      }
    } else if (binding === 'email') {
      const e = payload.data.email;
      if (!e) throw new Fail(14, 'an email binding without sender and recipients');
      if (!opts.email) { verdict = 'verified_unbound'; ok(14, 'email context unknown to the verifier'); }
      else {
        const from = opts.email.from.trim().toLowerCase();
        const toHash = await recipientsHash(opts.email.recipients);
        if (from !== e.from) { verdict = 'verified_email_other_sender'; ok(14, `signed by ${e.from}`); }
        else if (toHash !== e.to_hash) { verdict = 'verified_email_other_recipients'; ok(14, 'recipients differ'); }
        else { verdict = 'verified_email'; ok(14); }
      }
    } else {
      verdict = 'verified_unbound';
      ok(14, 'not bound to a page');
    }

    // 15
    if (record.withdrawn) {
      try {
        const w = await verifyAppended<{ id: string; at: string }>(record.withdrawn.jws, record.id, anchors, now());
        if (w.at !== record.withdrawn.at) throw new Error('withdrawal date differs from its signature');
        result.withdrawn = { at: w.at };
        verdict = 'withdrawn';
      } catch (e) { throw new Fail(15, msg(e)); }
    } else result.withdrawn = null;
    ok(15);

    // 16
    if (delegated) {
      try {
        const st = jwsClaims<DelegationClaims>(parseCompactJws(record.delegation!.statement));
        const exp = new Date(st.expires_at).getTime();
        const iat = new Date(st.iat).getTime();
        if (!(exp - iat <= 24 * 3600 * 1000)) throw new Error('delegation window exceeds 24 hours');
        if (!(asOf.getTime() <= exp)) throw new Error('the delegation had expired when this was signed');
        if (st.site !== payload.data.site) throw new Error('delegation is for another site');
        if (st.agent_name !== record.delegation!.agent_name) throw new Error('agent name differs from the delegation');
        result.delegation = { agentName: st.agent_name, humanSubject: record.delegation!.human_subject };
        if (verdict !== 'withdrawn') verdict = 'delegated';
      } catch (e) { throw new Fail(16, msg(e)); }
    }
    ok(16);

    // 17
    const relation: NonNullable<VerifyResult['relation']> = {};
    if (payload.data.co_signs) {
      const original = await opts.fetchRecord(payload.data.co_signs);
      if (original.status === 'ok') {
        const o = asRecord(original.record, payload.data.co_signs);
        if (o.payload.data.hash !== payload.data.hash || o.payload.data.url !== payload.data.url || o.payload.data.binding !== payload.data.binding) {
          throw new Fail(17, 'co-signature does not match the original text, URL and binding');
        }
        relation.coSigns = o.id;
      } else if (original.status === 'not_found') throw new Fail(17, 'the co-signed record does not exist');
      else relation.coSigns = payload.data.co_signs;
    }
    if (payload.data.in_reply_to) relation.inReplyTo = payload.data.in_reply_to;
    ok(17);

    // 18
    try {
      if (record.co_signers) {
        const c = await verifyAppended<{ id: string; count: number }>(record.co_signers.jws, record.id, anchors, now());
        if (c.count !== record.co_signers.count) throw new Error('co-signer count differs from its signature');
        relation.coSignerCount = c.count;
      }
      if (record.reports) {
        const r = await verifyAppended<{ id: string; count: number; reasons: Record<string, number> }>(record.reports.jws, record.id, anchors, now());
        if (r.count !== record.reports.count) throw new Error('report count differs from its signature');
        result.reports = { count: r.count, reasons: r.reasons };
      }
      if (record.log) {
        // A tree head names no record, so it is verified without the id check.
        const sth = await verifyAppendedNoId<{ tree_size: number; root: string }>(record.log.sth, anchors, now());
        if (ts.status === 'confirmed' && record.timestamp.merkle) {
          if (sth.root !== record.timestamp.merkle.root || sth.tree_size !== record.timestamp.merkle.size) throw new Error('the tree head does not match the inclusion proof');
        }
      }
    } catch (e) { throw new Fail(18, msg(e)); }
    if (Object.keys(relation).length > 0) result.relation = relation;
    ok(18);

    result.verdict = verdict;
    return result;
  } catch (e) {
    if (e instanceof Fail) {
      steps.push({ step: e.step, name: STEP_NAMES[e.step]!, ok: false, detail: e.message });
      result.verdict = e.verdict;
      result.reason = e.message;
      result.failedStep = e.step;
      return result;
    }
    steps.push({ step: 0, name: 'verifier', ok: false, detail: msg(e) });
    result.verdict = 'not_verified';
    result.reason = `verifier error: ${msg(e)}`;
    return result;
  }
}

interface DelegationClaims {
  order: string;
  agent_public_key: JsonWebKey;
  agent_name: string;
  site: string;
  expires_at: string;
  max_marks: number;
  iat: string;
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function presenceStep(e: unknown): number {
  const m = msg(e);
  if (/grade|channel|verdict/.test(m)) return 10;
  if (/aud|nonce|expired|dated|cti|sub|ckt|countersig/.test(m)) return 9;
  return 8;
}

function isDelegated(record: MarkRecord): boolean {
  return record.delegation !== undefined && record.delegation !== null;
}

function asRecord(raw: unknown, id: string): MarkRecord {
  const r = raw as Partial<MarkRecord> | null;
  if (!r || typeof r !== 'object') throw new Fail(2, 'the record is not an object');
  if (r.v !== 1) throw new Fail(2, `unsupported record version ${String(r.v)}`);
  if (r.id !== id) throw new Fail(2, 'the record carries a different id');
  if (!r.payload || typeof r.payload !== 'object') throw new Fail(2, 'the record has no payload');
  const s = r.signature;
  if (!s || typeof s.device !== 'string' || !Array.isArray(s.certificate_chain) || !Array.isArray(s.paired_chain)) throw new Fail(2, 'the record has no usable signature block');
  if (!r.timestamp || typeof r.timestamp !== 'object') throw new Fail(2, 'the record has no timestamp block');
  return r as MarkRecord;
}

function checkPayload(p: Payload, record: MarkRecord, marker: Marker, delegated: boolean): void {
  if (p.v !== 1) throw new Fail(11, `unsupported payload version ${String(p.v)}`);
  if (p.purpose !== 'content') throw new Fail(11, `payload purpose is ${p.purpose}, not content`);
  if (p.aud !== MARK_AUDIENCE) throw new Fail(11, `payload aud is ${p.aud}`);
  if (p.requester?.origin !== MARK_AUDIENCE) throw new Fail(11, 'payload requester is not ZOREAL Mark');
  if (!p.data || typeof p.data !== 'object') throw new Fail(11, 'payload has no data');
  if (!p.visible || typeof p.visible.hash !== 'string') throw new Fail(11, 'payload has no visible hash');
  if (!isValidId(p.order)) throw new Fail(11, 'payload order is not a valid id');
  if (record.kind !== p.data.kind) throw new Fail(11, 'record kind differs from the payload');
  const expectedContext = p.data.binding === 'email' ? `mailto:${p.data.site}` : `https://${p.data.site}`;
  if (p.context !== expectedContext) throw new Fail(11, `payload context ${p.context} does not match the site`);
  if (p.data.url !== null && p.data.url !== undefined && siteOf(p.data.url) !== p.data.site) throw new Fail(11, 'the site is not the registrable domain of the URL');
  if ((p.data.binding === 'none' || p.data.binding === 'email') && p.data.url) throw new Fail(11, 'an unbound record names a URL');
  if (marker === 'delegated' && !delegated) throw new Fail(16, 'a human Mark found under the delegated marker');
  if (marker === 'signed' && delegated) throw new Fail(16, 'a delegated Mark found under the signed marker');
}

function attachedClaims(c: PresenceClaims): VerifyResult['claims'] {
  const over: number[] = [];
  for (const n of [13, 16, 18, 21, 65] as const) if ((c as unknown as Record<string, unknown>)[`age_over_${n}`] === true) over.push(n);
  const out: NonNullable<VerifyResult['claims']> = {};
  if (over.length) out.age_over = over;
  if (typeof c.nationality === 'string') out.nationality = c.nationality;
  return Object.keys(out).length ? out : undefined;
}

function timeOf(ts: TimestampResult, record: MarkRecord): NonNullable<VerifyResult['time']> {
  if (ts.status === 'confirmed') return { status: 'confirmed', at: ts.genTime.toISOString() };
  if (ts.status === 'pending') return { status: 'unconfirmed', at: record.created_at ?? null, detail: 'timestamp pending' };
  return { status: 'unconfirmed', at: record.created_at ?? null, detail: ts.reason };
}

function safeNormalise(url: string): string | null {
  try { return normaliseUrl(url); } catch { return null; }
}

async function recipientsHash(recipients: string[]): Promise<string> {
  const sorted = recipients.map((r) => r.trim().toLowerCase()).filter(Boolean).sort();
  return toHex(await sha256(utf8(sorted.join(','))));
}

async function verifyAgentSignature(payload: Payload, signatureB64: string, jwk: JsonWebKey, humanLeafDer: Uint8Array): Promise<void> {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new Error('the agent key is not P-256');
  const expectedCert = toBase64Url(await sha256(humanLeafDer));
  if (payload.cert !== expectedCert) throw new Error('payload.cert does not name the delegating human certificate');
  const sig = fromBase64Url(signatureB64);
  if (sig.length !== 64) throw new Error(`agent signature is ${sig.length} bytes, not 64`);
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const message = concat(await jcsHash(payload), utf8(payload.order), utf8(payload.aud));
  if (!(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig as BufferSource, message as BufferSource))) {
    throw new Error('the agent signature does not verify under the delegated key');
  }
}

export { canonicalText, fromUtf8 };
export type { Binding, Grade };
