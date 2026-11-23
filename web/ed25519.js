// Ed25519 keys from a 32-byte seed, via WebCrypto or the vendored
// noble-ed25519. WebKit has had an open bug about incorrect Ed25519
// signatures (bug 262499), so WebCrypto is only used if it reproduces the
// RFC 8032 test vectors, and every WebCrypto signature is checked before use.

import * as noble from "./vendor/noble-ed25519.js";
import { concat, fromHex, hex } from "./sshsig.js";

const PKCS8_PREFIX = fromHex("302e020100300506032b657004220420");

// RFC 8032 section 7.1, tests 1-3: seed, public key, message, signature.
const VECTORS = [
  [
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  ],
  [
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "72",
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  ],
  [
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "af82",
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  ],
];

// Key constructors copy the seed so callers can wipe theirs.

async function nobleKey(seed) {
  seed = seed.slice();
  const pub = await noble.getPublicKeyAsync(seed);
  return { impl: "noble", pub, sign: (data) => noble.signAsync(data, seed) };
}

async function importWebCrypto(seed) {
  return crypto.subtle.importKey("pkcs8", concat(PKCS8_PREFIX, seed), { name: "Ed25519" }, false, ["sign"]);
}

async function webcryptoSign(key, data) {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, data));
}

async function webcryptoKey(seed) {
  seed = seed.slice();
  const pub = await noble.getPublicKeyAsync(seed);
  const key = await importWebCrypto(seed);
  return {
    impl: "webcrypto",
    pub,
    sign: async (data) => {
      const sig = await webcryptoSign(key, data);
      if (await noble.verifyAsync(sig, data, pub)) return sig;
      console.warn("WebCrypto produced an invalid Ed25519 signature; using noble");
      onFallback?.();
      return noble.signAsync(data, seed);
    },
  };
}

let onFallback = null;
export function onWebCryptoFallback(fn) {
  onFallback = fn;
}

const RAW_SIGNERS = {
  webcrypto: async (seed, msg) => webcryptoSign(await importWebCrypto(seed), msg),
  noble: (seed, msg) => noble.signAsync(msg, seed),
};

// selfTest checks an implementation against the RFC 8032 vectors, without
// the verify-and-fall-back wrapper so WebCrypto is judged on its own.
export async function selfTest(name) {
  try {
    for (const [seed, pub, msg, sig] of VECTORS) {
      if (hex(await noble.getPublicKeyAsync(fromHex(seed))) !== pub) return { ok: false, error: "public key mismatch" };
      if (hex(await RAW_SIGNERS[name](fromHex(seed), fromHex(msg))) !== sig) {
        return { ok: false, error: "signature mismatch on an RFC 8032 vector" };
      }
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e?.message ?? e) };
  }
}

// chooseImpl picks the implementation: "webcrypto" or "noble" force one,
// "auto" prefers WebCrypto when it passes the self-test.
export async function chooseImpl(pref = "auto") {
  if (pref === "noble") return { name: "noble", fromSeed: nobleKey };
  const t = await selfTest("webcrypto");
  if (pref === "webcrypto" || t.ok) return { name: "webcrypto", fromSeed: webcryptoKey, test: t };
  return { name: "noble", fromSeed: nobleKey, test: t };
}

// deriveSeed mirrors internal/keyderive: HKDF-SHA-256 over the PRF output
// with an empty salt and a fixed info string.
export async function deriveSeed(prf, info) {
  const ikm = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode(info) },
    ikm,
    256,
  );
  return new Uint8Array(bits);
}
