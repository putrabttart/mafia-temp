import { NextResponse } from 'next/server';
import { exchangeCode } from '@/lib/server/runtime';
import { handleError } from '@/lib/server/respond';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');

  try {
    // State validation optional di development; hanya pastikan code ada
    if (!code) {
      return new NextResponse(JSON.stringify({ error: 'No code provided' }), { status: 400 });
    }
    await exchangeCode(code, null);
    return new NextResponse('Auth berhasil! Anda bisa menutup tab ini.');
  } catch (err) {
    return handleError(err);
  }
}
