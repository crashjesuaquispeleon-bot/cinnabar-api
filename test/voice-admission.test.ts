import { exportPKCS8, generateKeyPair, jwtVerify } from "jose";
import { env } from "cloudflare:workers";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { issueVoiceAdmissionToken, voiceBrokerConfigured } from "../src/voice-admission";
import { installFakeIssuer, login, type Client } from "./helpers";

const open: Client[] = [];
const adminRequests: string[] = [];
const savedEnvironment: Record<string, string | undefined> = {};
const voiceEnvironmentKeys = [
  "VOICE_ADMISSION_PRIVATE_KEY",
  "VOICE_ADMISSION_ISSUER",
  "VOICE_ADMISSION_AUDIENCE",
  "VOICE_SFU_ADMIN_URL",
  "VOICE_SFU_ADMIN_TOKEN",
] as const;

function track(client: Client): Client {
  open.push(client);
  return client;
}

beforeAll(() => {
  installFakeIssuer((url) => {
    if (!url.startsWith("https://voice.test/")) return undefined;
    adminRequests.push(url);
    return new Response(null, { status: 204 });
  });
});

afterEach(async () => {
  await Promise.all(open.splice(0).map((client) => (client.close(), client.closed)));
  Object.assign(env, savedEnvironment);
  adminRequests.length = 0;
});

async function configureBroker() {
  for (const key of voiceEnvironmentKeys) {
    if (!(key in savedEnvironment)) savedEnvironment[key] = env[key];
  }
  const keys = await generateKeyPair("EdDSA", { extractable: true });
  Object.assign(env, {
    VOICE_ADMISSION_PRIVATE_KEY: await exportPKCS8(keys.privateKey),
    VOICE_ADMISSION_ISSUER: "https://api.test/voice",
    VOICE_ADMISSION_AUDIENCE: "cinnabar-voice-sfu",
    VOICE_SFU_ADMIN_URL: "https://voice.test",
    VOICE_SFU_ADMIN_TOKEN: "0123456789abcdef0123456789abcdef",
  });
  return keys;
}

describe("voice admission signing", () => {
  it("signs an EdDSA lease with broker-derived identity, partida IDs and a two-minute expiry", async () => {
    const keys = await configureBroker();
    expect(voiceBrokerConfigured(env)).toBe(true);
    const now = Date.now();
    const roomID = "00112233-4455-6677-8899-aabbccddeeff";
    const sessionID = "10112233-4455-6677-8899-aabbccddeeff";
    const tokenID = "20112233-4455-6677-8899-aabbccddeeff";
    const result = await issueVoiceAdmissionToken(env, {
      xuid: "2535400000000001",
      roomID,
      sessionID,
      tokenID,
      now,
      ttlSeconds: 120,
    });
    expect(result).not.toBeNull();
    const verified = await jwtVerify(result!.token, keys.publicKey, {
      issuer: "https://api.test/voice",
      audience: "cinnabar-voice-sfu",
      currentDate: new Date(now),
    });
    expect(verified.protectedHeader).toMatchObject({ alg: "EdDSA", typ: "JWT" });
    expect(verified.payload).toMatchObject({
      sub: "2535400000000001",
      xuid: "2535400000000001",
      room_id: roomID,
      session_id: sessionID,
      jti: tokenID,
    });
    expect(result!.expiresAt - Number(verified.payload.iat)).toBe(120);
  });

  it("refuses to issue when production key or secure SFU revocation credentials are absent", async () => {
    expect(voiceBrokerConfigured({})).toBe(false);
    expect(await issueVoiceAdmissionToken({}, {
      xuid: "1",
      roomID: crypto.randomUUID(),
      sessionID: crypto.randomUUID(),
      tokenID: crypto.randomUUID(),
      now: Date.now(),
      ttlSeconds: 120,
    })).toBeNull();
    const envWithoutAdmin = {
      VOICE_ADMISSION_PRIVATE_KEY: "configured",
      VOICE_SFU_ADMIN_URL: "http://voice.test",
      VOICE_SFU_ADMIN_TOKEN: "0123456789abcdef0123456789abcdef",
    };
    expect(voiceBrokerConfigured(envWithoutAdmin)).toBe(false);
  });
});

describe("authenticated FriendHost voice membership", () => {
  it("issues only for a live authenticated room member and revokes a removed member", async () => {
    const keys = await configureBroker();
    const hostXuid = "2535400000000001";
    const guestXuid = "2535400000000002";
    const outsiderXuid = "2535400000000003";
    const host = track((await login({ xuid: hostXuid })).client);
    const guest = track((await login({ xuid: guestXuid })).client);
    const outsider = track((await login({ xuid: outsiderXuid })).client);

    const openID = crypto.randomUUID();
    host.send({ type: "voice_host_open", request_id: openID });
    const room = await host.next();
    expect(room).toMatchObject({ type: "voice_room", request_id: openID });
    expect(typeof room.room_id).toBe("string");
    expect(typeof room.session_id).toBe("string");

    const membersID = crypto.randomUUID();
    host.send({ type: "voice_host_members", request_id: membersID, members: [guestXuid] });
    expect(await host.next()).toEqual({
      type: "voice_members_updated",
      request_id: membersID,
      count: 2,
    });

    const admissionID = crypto.randomUUID();
    guest.send({ type: "voice_admission_request", request_id: admissionID });
    const admission = await guest.next();
    expect(admission).toMatchObject({ type: "voice_admission", request_id: admissionID });
    const jwt = await jwtVerify(admission.token as string, keys.publicKey, {
      issuer: "https://api.test/voice",
      audience: "cinnabar-voice-sfu",
    });
    expect(jwt.payload).toMatchObject({
      sub: guestXuid,
      xuid: guestXuid,
      room_id: room.room_id,
      session_id: room.session_id,
    });

    const outsiderRequestID = crypto.randomUUID();
    outsider.send({ type: "voice_admission_request", request_id: outsiderRequestID });
    expect(await outsider.next()).toEqual({
      type: "voice_error",
      request_id: outsiderRequestID,
      code: "not_in_room",
    });

    const removedID = crypto.randomUUID();
    host.send({ type: "voice_host_members", request_id: removedID, members: [] });
    expect(await host.next()).toEqual({
      type: "voice_members_updated",
      request_id: removedID,
      count: 1,
    });
    expect(adminRequests).toContain(
      `https://voice.test/v1/admin/rooms/${room.room_id}/admissions/${jwt.payload.jti}/revoke`,
    );

    const afterRemovalID = crypto.randomUUID();
    guest.send({ type: "voice_admission_request", request_id: afterRemovalID });
    expect(await guest.next()).toEqual({
      type: "voice_error",
      request_id: afterRemovalID,
      code: "not_in_room",
    });

    const closeID = crypto.randomUUID();
    host.send({ type: "voice_host_close", request_id: closeID });
    expect(await host.next()).toEqual({
      type: "voice_closed",
      request_id: closeID,
      sfu_closed: true,
    });
    expect(adminRequests).toContain(
      `https://voice.test/v1/admin/rooms/${room.room_id}/sessions/${room.session_id}/close`,
    );
  });

  it("does not deliver a signed admission after the host removes the member", async () => {
    await configureBroker();
    const host = track((await login({ xuid: "2535400000000011" })).client);
    const guest = track((await login({ xuid: "2535400000000012" })).client);

    const openID = crypto.randomUUID();
    host.send({ type: "voice_host_open", request_id: openID });
    const room = await host.next();
    const membersID = crypto.randomUUID();
    host.send({ type: "voice_host_members", request_id: membersID, members: ["2535400000000012"] });
    expect(await host.next()).toMatchObject({ type: "voice_members_updated", request_id: membersID, count: 2 });

    let announceSigning!: () => void;
    let releaseSigning!: () => void;
    const signingStarted = new Promise<void>((resolve) => { announceSigning = resolve; });
    const signingGate = new Promise<void>((resolve) => { releaseSigning = resolve; });
    const signSpy = vi.spyOn(crypto.subtle, "sign").mockImplementation(async () => {
      announceSigning();
      await signingGate;
      // A deterministic, correctly-sized Ed25519 signature is sufficient here:
      // this test asserts broker delivery/authorization, not cryptographic validity.
      return new Uint8Array(64).buffer;
    });

    try {
      guest.send({ type: "voice_admission_request", request_id: crypto.randomUUID() });
      await signingStarted;

      const removeID = crypto.randomUUID();
      host.send({ type: "voice_host_members", request_id: removeID, members: [] });
      expect(await host.next()).toEqual({
        type: "voice_members_updated",
        request_id: removeID,
        count: 1,
      });

      releaseSigning();
      expect(await guest.next()).toMatchObject({
        type: "voice_error",
        code: "not_in_room",
      });
    } finally {
      releaseSigning();
      signSpy.mockRestore();
    }
    expect(room.type).toBe("voice_room");
  });

  it("stops issuing admissions before waiting for the SFU room-close request", async () => {
    await configureBroker();
    const host = track((await login({ xuid: "2535400000000021" })).client);
    const guest = track((await login({ xuid: "2535400000000022" })).client);

    const openID = crypto.randomUUID();
    host.send({ type: "voice_host_open", request_id: openID });
    const room = await host.next();
    const membersID = crypto.randomUUID();
    host.send({ type: "voice_host_members", request_id: membersID, members: ["2535400000000022"] });
    expect(await host.next()).toMatchObject({ type: "voice_members_updated", request_id: membersID, count: 2 });

    const closeURL = `https://voice.test/v1/admin/rooms/${room.room_id}/sessions/${room.session_id}/close`;
    const fetchMock = vi.mocked(globalThis.fetch);
    const previousFetch = fetchMock.getMockImplementation();
    if (!previousFetch) throw new Error("Expected the fake issuer fetch mock to be installed");

    let announceClose!: () => void;
    let releaseClose!: () => void;
    const closeStarted = new Promise<void>((resolve) => { announceClose = resolve; });
    const closeGate = new Promise<void>((resolve) => { releaseClose = resolve; });
    fetchMock.mockImplementation(async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === closeURL) {
        announceClose();
        await closeGate;
        return new Response(null, { status: 204 });
      }
      return previousFetch(input, init);
    });

    try {
      const closeID = crypto.randomUUID();
      host.send({ type: "voice_host_close", request_id: closeID });
      await closeStarted;

      guest.send({ type: "voice_admission_request", request_id: crypto.randomUUID() });
      expect(await guest.next()).toMatchObject({
        type: "voice_error",
        code: "not_in_room",
      });

      releaseClose();
      expect(await host.next()).toEqual({
        type: "voice_closed",
        request_id: closeID,
        sfu_closed: true,
      });
    } finally {
      releaseClose();
      fetchMock.mockImplementation(previousFetch);
    }
  });

  it("replays the same open request but rotates the room for a new host-world lifecycle", async () => {
    await configureBroker();
    const host = track((await login({ xuid: "2535400000000006" })).client);
    const firstID = crypto.randomUUID();
    host.send({ type: "voice_host_open", request_id: firstID });
    const first = await host.next();
    host.send({ type: "voice_host_open", request_id: firstID });
    const replay = await host.next();
    expect(replay).toMatchObject({
      type: "voice_room",
      request_id: firstID,
      room_id: first.room_id,
      session_id: first.session_id,
    });

    const nextID = crypto.randomUUID();
    host.send({ type: "voice_host_open", request_id: nextID });
    const next = await host.next();
    expect(next).toMatchObject({ type: "voice_room", request_id: nextID });
    expect(next.room_id).not.toBe(first.room_id);
    expect(next.session_id).not.toBe(first.session_id);
    expect(adminRequests).toContain(
      `https://voice.test/v1/admin/rooms/${first.room_id}/sessions/${first.session_id}/close`,
    );
  });

  it("rejects a host-reported guest without a live authenticated Cinnabar session", async () => {
    await configureBroker();
    const hostXuid = "2535400000000004";
    const unavailableXuid = "2535400000000005";
    const host = track((await login({ xuid: hostXuid })).client);
    const openID = crypto.randomUUID();
    host.send({ type: "voice_host_open", request_id: openID });
    expect((await host.next()).type).toBe("voice_room");

    const membersID = crypto.randomUUID();
    host.send({ type: "voice_host_members", request_id: membersID, members: [unavailableXuid] });
    expect(await host.next()).toEqual({
      type: "voice_error",
      request_id: membersID,
      code: "member_unavailable",
    });
  });
});
