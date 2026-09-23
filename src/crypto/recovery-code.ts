import { SyncKitError } from "../core/errors.js";

/**
 * Recovery codes: 128 random bits as 26 Crockford base32 characters plus 2
 * check characters that catch typos, shown in seven groups of four. Shared by
 * participant recovery keys and snapshot recovery locks, on web and Android.
 * Codes are only ever generated; parsing rejects anything else, so a
 * user-chosen passphrase can never be used. Browser-independent: callers
 * supply randomness and SHA-256.
 */
export type RecoveryCodeCrypto = {
  randomBytes(length: number): Uint8Array;
  sha256(data: Uint8Array): Promise<Uint8Array>;
};

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const SECRET_BYTES = 16;
const SECRET_CHARACTERS = 26;
const CHECK_CHARACTERS = 2;

/** A new recovery code. Show it once; whoever holds it can use it. */
export async function generateRecoveryCode(crypto: RecoveryCodeCrypto): Promise<string> {
  const secret = crypto.randomBytes(SECRET_BYTES);
  try {
    const characters = encodeSecret(secret) + (await checkCharacters(secret, crypto));
    const groups: string[] = [];
    for (let index = 0; index < characters.length; index += 4) {
      groups.push(characters.slice(index, index + 4));
    }
    return groups.join("-");
  } finally {
    secret.fill(0);
  }
}

/**
 * The 16-byte secret in a recovery code. Tolerates case, spaces, and hyphens,
 * and reads I and L as 1 and O as 0. The caller zeroes the result.
 */
export async function parseRecoveryCode(
  code: string,
  crypto: Pick<RecoveryCodeCrypto, "sha256">,
): Promise<Uint8Array> {
  const normalized = code
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
  if (
    normalized.length !== SECRET_CHARACTERS + CHECK_CHARACTERS ||
    !/^[0-9A-HJKMNP-TV-Z]+$/.test(normalized)
  ) {
    throw new SyncKitError("key", "This is not a recovery code.");
  }
  const secret = decodeSecret(normalized.slice(0, SECRET_CHARACTERS));
  if ((await checkCharacters(secret, crypto)) !== normalized.slice(SECRET_CHARACTERS)) {
    secret.fill(0);
    throw new SyncKitError(
      "key",
      "This recovery code has a typo: it does not match its check characters.",
    );
  }
  return secret;
}

/** Whether `code` is a well-formed recovery code, for live input validation. */
export async function isRecoveryCodeWellFormed(
  code: string,
  crypto: Pick<RecoveryCodeCrypto, "sha256">,
): Promise<boolean> {
  try {
    (await parseRecoveryCode(code, crypto)).fill(0);
    return true;
  } catch {
    return false;
  }
}

/** 128 bits → 26 characters; the final 2 bits are zero padding. */
function encodeSecret(secret: Uint8Array): string {
  let output = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of secret) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += CROCKFORD.charAt((buffer >>> (bits - 5)) & 31);
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) output += CROCKFORD.charAt((buffer << (5 - bits)) & 31);
  return output;
}

function decodeSecret(characters: string): Uint8Array {
  const secret = new Uint8Array(SECRET_BYTES);
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const character of characters) {
    buffer = (buffer << 5) | CROCKFORD.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      secret[index++] = (buffer >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
    buffer &= (1 << bits) - 1;
  }
  if (index !== SECRET_BYTES || buffer !== 0) {
    secret.fill(0);
    throw new SyncKitError("key", "This is not a recovery code.");
  }
  return secret;
}

/** Two characters (10 bits) of SHA-256 over the secret, to catch typos. */
async function checkCharacters(
  secret: Uint8Array,
  crypto: Pick<RecoveryCodeCrypto, "sha256">,
): Promise<string> {
  const digest = await crypto.sha256(secret);
  const check = (((digest[0] ?? 0) << 8) | (digest[1] ?? 0)) >>> 6;
  return CROCKFORD.charAt((check >>> 5) & 31) + CROCKFORD.charAt(check & 31);
}
