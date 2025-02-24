import { simpleOnionRouter } from "./simpleOnionRouter";

export async function launchOnionRouters(n: number) {
  const servers = [];

  // Launch routers sequentially instead of in parallel
  for (let index = 0; index < n; index++) {
    try {
      const server = await simpleOnionRouter(index);
      servers.push(server);
      // Add small delay between launches
      await new Promise(resolve => setTimeout(resolve, 100));
    } catch (error) {
      console.error(`Failed to launch onion router ${index}:`, error);
      throw error;
    }
  }

  return servers;
}
