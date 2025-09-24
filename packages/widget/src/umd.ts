import * as mod from './index';

// Expose as a global for CDN usage
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api: any = (mod as any).default || (mod as any).fidbak || mod;
(globalThis as any).fidbak = api;
