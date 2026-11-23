// SSH wire encoding: public keys, signatures and SSHSIG armor.

export const enc = new TextEncoder();
const dec = new TextDecoder();

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function u32(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

export function sshString(v) {
  const b = typeof v === "string" ? enc.encode(v) : v;
  return concat(u32(b.length), b);
}

export function b64(bytes) {
  let s = "";
  for (const c of bytes) s += String.fromCharCode(c);
  return btoa(s);
}

export function fromB64(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export function b64url(bytes) {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  return fromB64(s + "=".repeat((4 - (s.length % 4)) % 4));
}

export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(s) {
  return Uint8Array.from(s.match(/../g) || [], (h) => parseInt(h, 16));
}

export function publicKeyBlob(pub) {
  return concat(sshString("ssh-ed25519"), sshString(pub));
}

export function authorizedKey(pub) {
  return "ssh-ed25519 " + b64(publicKeyBlob(pub));
}

export async function fingerprint(pub) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKeyBlob(pub)));
  return "SHA256:" + b64(h).replace(/=+$/, "");
}

const HASHES = { sha256: "SHA-256", sha512: "SHA-512" };

// sshsigSign produces an armored signature that `ssh-keygen -Y verify`
// accepts, following OpenSSH's PROTOCOL.sshsig.
export async function sshsigSign(sign, pub, message, namespace, hashAlg = "sha512") {
  const magic = enc.encode("SSHSIG");
  const h = new Uint8Array(await crypto.subtle.digest(HASHES[hashAlg], message));
  const signed = concat(magic, sshString(namespace), sshString(""), sshString(hashAlg), sshString(h));
  const sig = await sign(signed);
  const blob = concat(
    magic,
    u32(1),
    sshString(publicKeyBlob(pub)),
    sshString(namespace),
    sshString(""),
    sshString(hashAlg),
    sshString(concat(sshString("ssh-ed25519"), sshString(sig))),
  );
  const body = b64(blob).match(/.{1,70}/g).join("\n");
  return `-----BEGIN SSH SIGNATURE-----\n${body}\n-----END SSH SIGNATURE-----\n`;
}

export function text(bytes) {
  return dec.decode(bytes);
}
