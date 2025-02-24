import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { webcrypto } from "node:crypto";

type CryptoKey = webcrypto.CryptoKey;

import {
  generateRsaKeyPair,
  rsaEncrypt,
  rsaDecrypt,
  symEncrypt,
  symDecrypt,
  importSymKey,
  exportPubKey,
  exportPrvKey,
} from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let privateKey: CryptoKey;
  let publicKey: CryptoKey;
  let privateKeyStr: string;
  let publicKeyStr: string;
  let lastCircuit: number[] = [];
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  try {
    const keyPair = await generateRsaKeyPair();
    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;

    // Export both keys immediately
    publicKeyStr = await exportPubKey(publicKey);
    privateKeyStr = await exportPrvKey(privateKey);

    // Immediately register with the registry after key generation
    const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nodeId,
        pubKey: publicKeyStr
      })
    });

    if (!registryResponse.ok) {
      throw new Error(`Failed to register node: ${registryResponse.statusText}`);
    }

    console.log(`Node ${nodeId} registered successfully`);
  } catch (error) {
    console.error('Failed to initialize node:', error);
    throw error; // Re-throw to prevent initialization if registration fails
  }

  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination || null });
  });

  onionRouter.get("/getPrivateKey", async (req, res) => {
    res.json({ result: privateKeyStr });
  });

  onionRouter.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  onionRouter.post("/message", async (req, res) => {
    try {
      const { message, circuit = [] } = req.body;
      if (!message) {
        return res.status(400).json({ error: "Message required" });
      }

      // Update circuit first
      lastCircuit = [...circuit, nodeId];

      lastReceivedEncryptedMessage = message;

      // The first part is the encrypted symmetric key (344 chars for RSA-2048)
      const encryptedSymKey = message.substring(0, 344);
      const encryptedPayload = message.substring(344);

      // Decrypt the symmetric key using node's private key
      let symKey: CryptoKey;
      try {
        const symKeyStr = await rsaDecrypt(encryptedSymKey, privateKey);
        symKey = await importSymKey(symKeyStr);
        console.log(`Decrypted Symmetric Key: ${symKey}`);
      } catch (error) {
        console.error('Error decrypting symmetric key:', error);
        throw new Error('Failed to decrypt symmetric key');
      }

      // Decrypt the payload using the symmetric key
      let decrypted;
      try {
        decrypted = await symDecrypt(symKey, encryptedPayload);
        console.log(`Decrypted Payload: ${decrypted}`);
      } catch (error) {
        console.error('Error decrypting payload:', error);
        throw new Error('Failed to decrypt payload');
      }

      // Extract destination and remaining message
      const destination = parseInt(decrypted.substring(0, 10));
      if (isNaN(destination)) {
        throw new Error('Invalid destination port');
      }

      // Store the destination before forwarding
      lastMessageDestination = destination;
      const remainingMessage = decrypted.substring(10);

      lastReceivedDecryptedMessage = remainingMessage;

      // Forward the message with updated circuit
      await fetch(`http://localhost:${destination}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: remainingMessage,
          circuit: lastCircuit  // Pass the circuit along
        })
      });

      return res.json({ success: true });
    } catch (error) {
      console.error('Error processing message:', error);
      return res.status(500).json({ error: 'Failed to process message' });
    }
  });

  const startServer = (port: number) => {
    const server = onionRouter.listen(port, () => {
      console.log(`Onion router ${nodeId} is listening on port ${port}`);
    });

    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`Port ${port} is already in use, trying next port...`);
        server.close(() => startServer(port + 1));
      } else {
        console.error('Server error:', err);
      }
    });

    return server;
  };

  return startServer(BASE_ONION_ROUTER_PORT + nodeId);
}