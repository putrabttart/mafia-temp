import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://xkacsdvkpniafudevwvq.supabase.co';
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'sb_publishable_BpsbHQApiJVo41bccRj3-g_MgL6Ck2X';

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
