import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { createRandomSymmetricKey, exportSymKey, symEncrypt, rsaEncrypt } from "../crypto";

// Add interface for the registry response
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

  _user.post("/message", (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: "Message required." });

    lastReceivedMessage = message;
    res.json({ message: "Message received successfully." });
  });

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body as SendMessageBody;

    try {
      // Get node registry with proper typing
      const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const { nodes } = await registryResponse.json() as RegistryResponse;

      // Select 3 random distinct nodes
      const circuit = selectRandomNodes(nodes, 3);

      // Create symmetric keys for each node
      const symmetricKeys = await Promise.all(
        circuit.map(() => createRandomSymmetricKey())
      );

      // Build the onion layers
      let finalDestination = `${String(BASE_USER_PORT + destinationUserId).padStart(10, '0')}`;
      let currentMessage = message;

      // Create layers from inside out
      for (let i = circuit.length - 1; i >= 0; i--) {
        // Export the symmetric key to string format
        const symKey = await exportSymKey(symmetricKeys[i]);

        // Encrypt the symmetric key with node's public key
        const encryptedSymKey = await rsaEncrypt(symKey, circuit[i].pubKey);

        // Encrypt the message and destination with symmetric key
        const encryptedPayload = await symEncrypt(
          symmetricKeys[i],
          finalDestination + currentMessage
        );

        // Combine encrypted symmetric key with encrypted payload
        currentMessage = encryptedSymKey + encryptedPayload;

        // Prepare next destination
        if (i > 0) {
          finalDestination = `${String(BASE_ONION_ROUTER_PORT + circuit[i].nodeId).padStart(10, '0')}`;
        }
      }

      // Send to entry node
      const entryNode = circuit[0];
      await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + entryNode.nodeId}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: currentMessage })
      });

      lastSentMessage = message;
      res.json({ success: true });

    } catch (error) {
      console.error('Error sending message:', error);
      res.status(500).json({ error: 'Failed to send message' });
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}

// Helper function to select random nodes
function selectRandomNodes(nodes: Array<{ nodeId: number; pubKey: string }>, count: number) {
  const shuffled = [...nodes].sort(() => 0.5 - Math.random());
  return shuffled.slice(0, count);
}