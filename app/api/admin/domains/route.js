import { addDomain, adminDomains, requireAdmin } from '@/lib/server/runtime';
import { respond, handleError } from '@/lib/server/respond';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request) {
  try {
    requireAdmin(request);
    const payload = adminDomains();
    return respond(payload);
  } catch (err) {
    return handleError(err);
  }
}

export async function POST(request) {
  try {
    requireAdmin(request);
    const body = await request.json();
    const payload = addDomain(body.name || '');
    return respond(payload);
  } catch (err) {
    return handleError(err);
  }
}
