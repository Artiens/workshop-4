import { webcrypto } from "node:crypto";

// Add type definition for CryptoKey
type CryptoKey = webcrypto.CryptoKey;

export interface RSAKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

// Generate RSA key pair
export async function generateRsaKeyPair(): Promise<RSAKeyPair> {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: "SHA-256" },
    },
    true,
    ["encrypt", "decrypt"]
  );
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

// Export public key to base64 string
export async function exportPubKey(key: CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey("spki", key);
  return Buffer.from(exported).toString('base64');
}

// Export private key to base64 string
export async function exportPrvKey(key: CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey("pkcs8", key);
  return Buffer.from(exported).toString('base64');
}

// Import public key from base64 string
export async function importPubKey(keyStr: string): Promise<CryptoKey> {
  const keyBuffer = Buffer.from(keyStr, 'base64');
  return await webcrypto.subtle.importKey(
    "spki",
    keyBuffer,
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-256" }
    },
    true,
    ["encrypt"]
  );
}

// Import private key from base64 string
export async function importPrvKey(keyStr: string): Promise<CryptoKey> {
  const keyBuffer = Buffer.from(keyStr, 'base64');
  return await webcrypto.subtle.importKey(
    "pkcs8",
    keyBuffer,
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-256" }
    },
    true,
    ["decrypt"]
  );
}

// RSA encryption using public key
export async function rsaEncrypt(data: string, publicKey: string | CryptoKey): Promise<string> {
  let cryptoKey: CryptoKey;
  if (typeof publicKey === 'string') {
    cryptoKey = await importPubKey(publicKey);
  } else {
    cryptoKey = publicKey;
  }

  const encoded = new TextEncoder().encode(data);
  const encrypted = await webcrypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    cryptoKey,
    encoded
  );
  return Buffer.from(encrypted).toString('base64');
}

// RSA decryption using private key
export async function rsaDecrypt(encryptedData: string, privateKey: string | CryptoKey): Promise<string> {
  let cryptoKey: CryptoKey;
  if (typeof privateKey === 'string') {
    cryptoKey = await importPrvKey(privateKey);
  } else {
    cryptoKey = privateKey;
  }

  const encrypted = Buffer.from(encryptedData, 'base64');
  const decrypted = await webcrypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    cryptoKey,
    encrypted
  );
  return new TextDecoder().decode(decrypted);
}

// Generate random symmetric key
export async function createRandomSymmetricKey(): Promise<CryptoKey> {
  return await webcrypto.subtle.generateKey(
    {
      name: "AES-CBC",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
}

// Export symmetric key to string
export async function exportSymKey(key: CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey("raw", key);
  return Buffer.from(exported).toString('base64');
}

// Import symmetric key from string
export async function importSymKey(keyStr: string): Promise<CryptoKey> {
  const keyBuffer = Buffer.from(keyStr, 'base64');
  return await webcrypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "AES-CBC" },
    true,
    ["encrypt", "decrypt"]
  );
}

// Symmetric encryption
export async function symEncrypt(key: string | CryptoKey, data: string): Promise<string> {
  let cryptoKey: CryptoKey;
  if (typeof key === 'string') {
    cryptoKey = await importSymKey(key);
  } else {
    cryptoKey = key;
  }

  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const encoded = new TextEncoder().encode(data);

  const encrypted = await webcrypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv
    },
    cryptoKey,
    encoded
  );

  return JSON.stringify({
    iv: Buffer.from(iv).toString('base64'),
    data: Buffer.from(encrypted).toString('base64')
  });
}

// Symmetric decryption
export async function symDecrypt(key: string | CryptoKey, encryptedData: string): Promise<string> {
  let cryptoKey: CryptoKey;
  if (typeof key === 'string') {
    cryptoKey = await importSymKey(key);
  } else {
    cryptoKey = key;
  }

  const { iv, data } = JSON.parse(encryptedData);

  const decrypted = await webcrypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: Buffer.from(iv, 'base64')
    },
    cryptoKey,
    Buffer.from(data, 'base64')
  );

  return new TextDecoder().decode(decrypted);
}
