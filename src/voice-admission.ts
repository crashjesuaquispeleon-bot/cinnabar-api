import { importPKCS8, SignJWT } from "jose";

export const DEFAULT_VOICE_ISSUER = "https://api.cinnabar.gg/voice";
export const DEFAULT_VOICE_AUDIENCE = "cinnabar-voice-sfu";

const ADMIN_TOKEN = /^[\x21-\x7e]{32}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

type VoiceEnvironment = Pick<Env,
  "VOICE_ADMISSION_PRIVATE_KEY" | "VOICE_ADMISSION_ISSUER" | "VOICE_ADMISSION_AUDIENCE" |
  "VOICE_SFU_ADMIN_URL" | "VOICE_SFU_ADMIN_TOKEN"
>;

export interface VoiceAdmissionInput {
  xuid: string;
  roomID: string;
  sessionID: string;
  tokenID: string;
  now: number;
  ttlSeconds: number;
}

export interface IssuedVoiceAdmission {
  token: string;
  expiresAt: number;
}

/** Refuses to enable admissions until both signing and immediate SFU revocation are configured. */
export function voiceBrokerConfigured(env: VoiceEnvironment): boolean {
  if (!env.VOICE_ADMISSION_PRIVATE_KEY || !env.VOICE_SFU_ADMIN_URL ||
      !env.VOICE_SFU_ADMIN_TOKEN || !ADMIN_TOKEN.test(env.VOICE_SFU_ADMIN_TOKEN)) return false;
  try {
    const admin = new URL(env.VOICE_SFU_ADMIN_URL);
    const issuer = new URL(env.VOICE_ADMISSION_ISSUER?.trim() || DEFAULT_VOICE_ISSUER);
    const audience = env.VOICE_ADMISSION_AUDIENCE?.trim() || DEFAULT_VOICE_AUDIENCE;
    return admin.protocol === "https:" && !admin.username && !admin.password &&
      (admin.pathname === "/" || admin.pathname === "") && !admin.search && !admin.hash &&
      issuer.protocol === "https:" && !issuer.username && !issuer.password &&
      audience.length > 0 && audience.length <= 256;
  } catch {
    return false;
  }
}

/** Signs an EdDSA token whose identity and partida fields originate from Hub state, never a request body. */
export async function issueVoiceAdmissionToken(
  env: VoiceEnvironment,
  input: VoiceAdmissionInput,
): Promise<IssuedVoiceAdmission | null> {
  if (!env.VOICE_ADMISSION_PRIVATE_KEY || !/^\d{1,20}$/.test(input.xuid) ||
      !UUID.test(input.roomID) || !UUID.test(input.sessionID) || !UUID.test(input.tokenID) ||
      !Number.isSafeInteger(input.now) || !Number.isSafeInteger(input.ttlSeconds) ||
      input.ttlSeconds < 1 || input.ttlSeconds > 300) return null;
  const issuer = env.VOICE_ADMISSION_ISSUER?.trim() || DEFAULT_VOICE_ISSUER;
  const audience = env.VOICE_ADMISSION_AUDIENCE?.trim() || DEFAULT_VOICE_AUDIENCE;
  if (!issuer.startsWith("https://") || audience.length === 0) return null;
  const issuedAt = Math.floor(input.now / 1000);
  const expiresAt = issuedAt + input.ttlSeconds;
  try {
    const privateKey = await importPKCS8(env.VOICE_ADMISSION_PRIVATE_KEY, "EdDSA");
    const token = await new SignJWT({
      xuid: input.xuid,
      room_id: input.roomID,
      session_id: input.sessionID,
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject(input.xuid)
      .setJti(input.tokenID)
      .setIssuedAt(issuedAt)
      .setNotBefore(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(privateKey);
    return { token, expiresAt };
  } catch {
    // A malformed/mismatched secret disables admission; never close an authenticated API socket.
    return null;
  }
}

/** Calls only canonical SFU admin endpoints over HTTPS; bearer credentials are never redirected or logged. */
export async function voiceSfuAdmin(env: VoiceEnvironment, path: string): Promise<boolean> {
  if (!voiceBrokerConfigured(env) ||
      !/^\/v1\/admin\/rooms\/[0-9a-f-]{36}\/(?:sessions\/[0-9a-f-]{36}\/close|admissions\/[0-9a-f-]{36}\/revoke)$/.test(path)) {
    return false;
  }
  try {
    const base = new URL(env.VOICE_SFU_ADMIN_URL!);
    const response = await fetch(new URL(path, base), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.VOICE_SFU_ADMIN_TOKEN!}`,
        "Cache-Control": "no-store",
      },
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
    });
    return response.status === 204;
  } catch {
    return false;
  }
}
