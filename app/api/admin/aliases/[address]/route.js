import { deleteAlias, requireAdmin } from '@/lib/server/runtime';
import { respond, handleError } from '@/lib/server/respond';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function DELETE(request, { params }) {
  try {
    requireAdmin(request);
    const payload = deleteAlias(params.address);
    return respond(payload);
  } catch (err) {
    return handleError(err);
  }
}
