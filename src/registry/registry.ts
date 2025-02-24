import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const nodes: Node[] = [];

function clearNodes() {
  nodes.length = 0;
}

export async function launchRegistry() {
  // Clear existing nodes when launching registry
  clearNodes();

  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // Implement the status route
  _registry.get("/status", (req, res) => {
    res.send('live');
  });

  // Implement the registerNode route
  _registry.post("/registerNode", (req: Request, res: Response) => {
    const { nodeId, pubKey } = req.body as RegisterNodeBody;

    if (typeof nodeId !== 'number' || typeof pubKey !== 'string') {
      return res.status(400).json({ error: 'Invalid request body' });
    }

    // Check if node already exists and replace it if it does
    const existingIndex = nodes.findIndex(n => n.nodeId === nodeId);
    if (existingIndex !== -1) {
      nodes[existingIndex] = { nodeId, pubKey };
    } else {
      nodes.push({ nodeId, pubKey });
    }

    return res.status(200).json({ success: true });
  });

  // Implement the getNodeRegistry route
  _registry.get("/getNodeRegistry", (req, res) => {
    res.json({ nodes });
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}