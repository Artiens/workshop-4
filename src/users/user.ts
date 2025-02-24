import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { symEncrypt, rsaEncrypt, exportSymKey, importPubKey } from "../crypto";
import { webcrypto } from "node:crypto";

interface RegistryResponse {
  nodes: Array<{
    nodeId: number;
    pubKey: string;
  }>;
}

let lastReceivedMessage: string | null = null;
let lastSentMessage: string | null = null;

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  let lastCircuit: number[] = [];
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  _user.post("/message", (req, res) => {
    const { message, circuit } = req.body;
    if (!message) {
      return res.status(400).json({ error: "Message required." });
    }

    lastReceivedMessage = message;
    if (circuit) {
      lastCircuit = circuit;
    }

    return res.send("success");
  });

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body as SendMessageBody;

    try {
      const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const { nodes } = await registryResponse.json() as RegistryResponse;

      const selectedNodes = selectRandomNodes(nodes, 3);
      const circuit = selectedNodes.map(node => node.nodeId);

      const symmetricKeys = await Promise.all(
        Array(3).fill(null).map(() => createRandomSymmetricKey())
      );

      // Start with final destination (user)
      let finalDestination = `${String(BASE_USER_PORT + destinationUserId).padStart(10, '0')}`;
      let currentMessage = message;

      // Build layers from last to first
      for (let i = circuit.length - 1; i >= 0; i--) {
        const symKey = symmetricKeys[i];
        const nodePublicKey = await importPubKey(selectedNodes[i].pubKey);

        const symKeyStr = await exportSymKey(symKey);
        const encryptedSymKey = await rsaEncrypt(symKeyStr, nodePublicKey);
        const encryptedPayload = await symEncrypt(symKey, finalDestination + currentMessage);

        currentMessage = encryptedSymKey + encryptedPayload;

        // Calculate next hop destination
        if (i > 0) {
          // For intermediate nodes, next destination is the next node in circuit
          finalDestination = `${String(BASE_ONION_ROUTER_PORT + circuit[i]).padStart(10, '0')}`;
        }
      }

      // Send to first node
      await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0]}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: currentMessage,
          circuit: []
        })
      });

      lastSentMessage = message;
      lastCircuit = circuit;
      return res.json({ success: true });
    } catch (error) {
      console.error('Error sending message:', error);
      return res.status(500).json({ error: 'Failed to send message' });
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}

function selectRandomNodes(nodes: Array<{ nodeId: number; pubKey: string }>, count: number) {
  // Fisher-Yates shuffle implementation
  const array = [...nodes];
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array.slice(0, count);
}

async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  return await webcrypto.subtle.generateKey(
    {
      name: "AES-CBC",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
}

