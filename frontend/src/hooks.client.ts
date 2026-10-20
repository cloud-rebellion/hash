import type { HandleClientError } from '@sveltejs/kit';
import { captureFlareRenderError } from './lib/flare-client';

// Returning undefined preserves SvelteKit's default sanitized fallback. Never
// inspect or forward the supplied error, navigation event, status or message.
export const handleError: HandleClientError = () => {
	try { captureFlareRenderError(); } catch { /* Error reporting must not throw. */ }
};
