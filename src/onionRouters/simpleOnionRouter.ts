import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import {
  generateRsaKeyPair,
  exportPubKey,
  exportPrvKey,
  importPrvKey,
  rsaDecrypt,
  importSymKey,
  symDecrypt
} from "../crypto";

let lastReceivedEncryptedMessage: string | null = null;
let lastReceivedDecryptedMessage: string | null = null;
let lastMessageDestination: number | null = null;

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // Generate RSA key pair using our crypto functions
  const keyPair = await generateRsaKeyPair();
  const publicKeyStr = await exportPubKey(keyPair.publicKey);
  const privateKeyStr = await exportPrvKey(keyPair.privateKey);

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
    res.json({ result: lastMessageDestination });
  });

  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privateKeyStr });
  });

  onionRouter.post("/message", async (req, res) => {
    try {
      const { message } = req.body;
      lastReceivedEncryptedMessage = message;

      // The first part of the message is the encrypted symmetric key
      // The rest is the encrypted payload
      const encryptedSymKey = message.substring(0, 344); // RSA-2048 output is 344 chars in base64
      const encryptedPayload = message.substring(344);

      // Decrypt the symmetric key using the node's private key
      const symKey = await rsaDecrypt(encryptedSymKey, keyPair.privateKey);

      // Decrypt the payload using the symmetric key
      const decrypted = await symDecrypt(symKey, encryptedPayload);

      // Extract destination and remaining message
      const destination = parseInt(decrypted.substring(0, 10));
      const remainingMessage = decrypted.substring(10);

      lastReceivedDecryptedMessage = remainingMessage;
      lastMessageDestination = destination;

      // Forward the message
      await fetch(`http://localhost:${destination}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: remainingMessage })
      });

      res.json({ success: true });
    } catch (error) {
      console.error('Error processing message:', error);
      res.status(500).json({ error: 'Failed to process message' });
    }
  });

  // Register node with registry
  try {
    await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nodeId, pubKey: publicKeyStr })
    });
  } catch (error) {
    console.error('Failed to register node:', error);
  }

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}