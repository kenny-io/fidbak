import { verifyClerkJWT, type AuthUser } from './jwt';

export type { AuthUser } from './jwt';

export async function getAuth(env: {
  CLERK_ISSUER?: string;
  CLERK_JWKS_URL?: string;
  CLERK_AUDIENCE?: string;
  CLERK_ISSUER_2?: string;
  CLERK_JWKS_URL_2?: string;
  FIDBAK_DEV_AUTOMIGRATE?: string;
}, request: Request): Promise<AuthUser | undefined> {
  const auth = request.headers.get('authorization') || request.headers.get('Authorization');
  if (!auth || !auth.toLowerCase().startsWith('bearer ')) return undefined;
  const token = auth.slice(7).trim();
  return verifyClerkJWT(env, token);
}
