import { adminAliases, requireAdmin } from '@/lib/server/runtime';
import { respond, handleError } from '@/lib/server/respond';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request) {
  try {
    requireAdmin(request);
    const payload = adminAliases();
    return respond(payload);
  } catch (err) {
    return handleError(err);
  }
}
