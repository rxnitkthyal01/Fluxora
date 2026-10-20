import { randomUUID } from 'node:crypto';

type Handler = (type: string, data: any) => void;
const handlers = new Map<string, Handler>();

export const pubsub = {
  subscribe(handler: Handler) {
    const id = randomUUID();
    handlers.set(id, handler);
    return () => { handlers.delete(id); };
  },
  publish(type: string, data: any) {
    // In a multi-instance production environment, this would publish to Redis or a message broker.
    // For a local developer tool, we use a central dispatcher that can be extended.
    for (const handler of handlers.values()) {
      handler(type, data);
    }
  }
};
