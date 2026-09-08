/**
 * The record and the verifier's result. The wire shape is decided outside this
 * package; the types here restate it so a caller cannot construct something the
 * verifier would not recognise.
 */

export type Binding = 'page' | 'email' | 'channel' | 'none';
export type Identity = 'persona' | 'legal_name' | 'organisation';
export type Purpose = 'content' | 'contract' | 'consent';
export type Kind = 'text' | 'image' | 'audio' | 'video' | 'page' | 'email' | 'chat' | 'file';
export type Grade = 'recent' | 'live' | 'delegated';

export interface LegalNameSubject {
  name: string;
  document_type: string;
  issuing_country: string;
  document_number: string;
}

export interface OrganisationSubject {
  legal_name: string;
  registration_number: string;
  country: string;
}

export interface MarkData {
  kind: Kind;
  hash_algorithm?: 'SHA-256';
  /** Lowercase hex SHA-256 of the canonical text (or of the file bytes). */
  hash: string;
  url: string | null;
  site: string;
  binding: Binding;
  email?: { from: string; to_hash: string };
  selector?: 'data-zoreal-mark' | 'article' | 'main';
  file?: { name: string; size: number };
  in_reply_to?: string;
  co_signs?: string;
  phash?: string;
}

/** The sign order envelope the phone signed. */
export interface Payload {
  v: 1;
  order: string;
  purpose: Purpose;
  context: string;
  identity: Identity;
  subject: string | LegalNameSubject | OrganisationSubject;
  /** base64url SHA-256 of the classical leaf certificate DER. */
  cert: string;
  visible: { hash: string; canonical: 'mark-text-v1' | 'none'; format: 'plaintext' | 'markdown' };
  data: MarkData;
  requester: { name: string; origin: string };
  aud: string;
  iat: string;
}

export interface JwsSignature {
  protected: string;
  signature: string;
}

/** JWS General JSON Serialization, RFC 7515 section 7.2. */
export interface JwsGeneral {
  payload: string;
  signatures: JwsSignature[];
}

export interface Assurance {
  uniqueness: string;
  verified_on: string;
  chip_liveness_proven: boolean;
  trust_tier: string;
  key_protection: string;
}

export interface MerkleProof {
  root: string;
  proof: string[];
  index: number;
  size: number;
}

export interface Timestamp {
  status: 'pending' | 'confirmed';
  tsa?: string;
  token?: string;
  merkle?: MerkleProof;
  gen_time?: string;
}

export interface Delegation {
  /** Compact JWS signed under the human's persona certificate; see verify.ts. */
  statement: string;
  human_subject: string;
  agent_name: string;
}

export interface MarkRecord {
  v: 1;
  id: string;
  kind: Kind;
  payload: Payload;
  signature: {
    device: string;
    certificate_chain: string[];
    paired_chain: string[];
    revocation: { classical: string; post_quantum: string };
  };
  presence: JwsGeneral;
  assurance: Assurance;
  timestamp: Timestamp;
  withdrawn: null | { at: string; jws: JwsGeneral };
  created_at: string;
  delegation?: Delegation;
  co_signers?: { count: number; first_at: string; last_at: string; jws: JwsGeneral };
  reports?: { count: number; reasons: Record<string, number>; jws: JwsGeneral };
  log?: { tree_size: number; sth: JwsGeneral };
}

export type FetchResult =
  | { status: 'ok'; record: unknown }
  | { status: 'not_found' }
  | { status: 'unavailable'; reason: string };

export type Verdict =
  | 'verified_here'
  | 'verified_in_channel'
  | 'verified_email'
  | 'verified_email_other_recipients'
  | 'verified_email_other_sender'
  | 'verified_other_page'
  | 'verified_unbound'
  | 'delegated'
  | 'withdrawn'
  | 'cannot_verify_now'
  | 'not_verified'
  | 'no_signature';

export interface StepResult {
  step: number;
  name: string;
  ok: boolean;
  /** One line, the real reason. */
  detail?: string;
}

export interface PresenceClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  cti: string;
  cnf: { ckt: string };
  zoreal: {
    grade: Grade;
    countersig_over: string;
    nonce: string;
    verdict: string;
    trust_tier: string;
    channel: string;
    scoring_profile?: string;
    cell?: string;
    session_ref?: string;
  };
  age_over_13?: boolean;
  age_over_16?: boolean;
  age_over_18?: boolean;
  age_over_21?: boolean;
  age_over_65?: boolean;
  nationality?: string;
}

export interface VerifyResult {
  verdict: Verdict;
  /** Present on not_verified, cannot_verify_now and no_signature. */
  reason?: string;
  /** Which step failed, when one did. */
  failedStep?: number;
  steps: StepResult[];
  record?: MarkRecord;
  identity?: Identity;
  subject?: Payload['subject'];
  site?: string;
  /** The URL the record was signed for, when bound. */
  signedUrl?: string | null;
  binding?: Binding;
  grade?: Grade;
  time?: { status: 'confirmed' | 'unconfirmed'; at: string | null; detail?: string };
  claims?: { age_over?: number[]; nationality?: string };
  withdrawn?: { at: string } | null;
  delegation?: { agentName: string; humanSubject: string };
  relation?: { coSigns?: string; inReplyTo?: string; coSignerCount?: number };
  reports?: { count: number; reasons: Record<string, number> };
  assurance?: Assurance;
}
