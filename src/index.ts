import { launchOnionRouters } from "./onionRouters/launchOnionRouters";
import { launchRegistry } from "./registry/registry";
import { launchUsers } from "./users/launchUsers";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "./config";

async function waitForServer(port: number, maxAttempts = 5): Promise<boolean> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(`http://localhost:${port}/status`);
      if (response.ok) {
        return true;
      }
    } catch (error) {
      await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second
    }
  }
  return false;
}

export async function launchNetwork(nbNodes: number, nbUsers: number) {
  // Launch registry first
  const registry = await launchRegistry();

  // Wait for registry to be ready
  const registryReady = await waitForServer(REGISTRY_PORT);
  if (!registryReady) {
    throw new Error('Registry failed to start');
  }

  // Launch all nodes with delay between each
  const onionRouters = await launchOnionRouters(nbNodes);

  // Verify all nodes are up
  for (let i = 0; i < nbNodes; i++) {
    const nodeReady = await waitForServer(BASE_ONION_ROUTER_PORT + i);
    if (!nodeReady) {
      throw new Error(`Node ${i} failed to start`);
    }
  }

  // Launch users after nodes are ready
  const userServers = await launchUsers(nbUsers);

  return [registry, ...onionRouters, ...userServers];
}

