// src/laravelEncrypt.ts
import crypto from "node:crypto";

type SupportedCipher = "aes-128-cbc" | "aes-256-cbc";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function parseAppKey(appKey: string): Buffer {
  const k = String(appKey ?? "").trim();
  if (!k) throw new Error("Missing APP_KEY");

  if (k.startsWith("base64:")) {
    return Buffer.from(k.slice("base64:".length), "base64");
  }

  return Buffer.from(k, "utf8");
}

function assertKeyLength(key: Buffer, cipher: SupportedCipher) {
  const need = cipher === "aes-128-cbc" ? 16 : 32;
  if (key.length !== need) {
    throw new Error(`Bad key length: got ${key.length}, expected ${need} for ${cipher}`);
  }
}

export function generateBase32Secret(chars = 32): string {
  const bytesNeeded = Math.ceil((chars * 5) / 8);
  const buf = crypto.randomBytes(bytesNeeded);

  let bits = 0;
  let value = 0;
  let out = "";

  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;

    while (bits >= 5 && out.length < chars) {
      const idx = (value >> (bits - 5)) & 31;
      out += BASE32_ALPHABET[idx];
      bits -= 5;
    }

    if (out.length >= chars) break;
  }

  while (out.length < chars) {
    out += BASE32_ALPHABET[crypto.randomInt(0, 32)];
  }

  return out;
}

function phpSerializeString(s: string): string {
  const byteLen = Buffer.byteLength(s, "utf8");
  return `s:${byteLen}:"${s}";`;
}

function laravelEncryptPayload(
  plainText: string,
  opts: { appKey: string; cipher?: SupportedCipher }
): string {
  const cipher: SupportedCipher = (opts.cipher ?? "aes-128-cbc") as SupportedCipher;

  const key = parseAppKey(opts.appKey);
  assertKeyLength(key, cipher);

  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv(cipher, key, iv);

  const value = c.update(String(plainText), "utf8", "base64") + c.final("base64");
  const ivB64 = iv.toString("base64");

  const mac = crypto.createHmac("sha256", key).update(ivB64 + value, "utf8").digest("hex");

  const json = JSON.stringify({ iv: ivB64, value, mac, tag: "" });
  return Buffer.from(json, "utf8").toString("base64");
}

export function laravelEncrypt(
  value: string,
  opts: { appKey: string; cipher?: SupportedCipher; serialize?: boolean }
): string {
  const serialize = opts.serialize !== false; 
  const plain = serialize ? phpSerializeString(value) : value;
  return laravelEncryptPayload(plain, { appKey: opts.appKey, cipher: opts.cipher });
}

export function makeLaravelEncryptedAuthenticatorSecret(env: {
  APP_KEY: string;
  APP_CIPHER?: SupportedCipher;
}): { plainSecret: string; encryptedSecret: string } {
  const plainSecret = generateBase32Secret(32);
  const encryptedSecret = laravelEncrypt(plainSecret, {
    appKey: env.APP_KEY,
    cipher: env.APP_CIPHER ?? "aes-128-cbc",
    serialize: true
  });
  return { plainSecret, encryptedSecret };
}
