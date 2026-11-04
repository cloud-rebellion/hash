import type { HandleClientError } from '@sveltejs/kit';
import { captureFlareRenderError } from './lib/flare-client';

// Returning undefined preserves SvelteKit's default sanitized fallback. The
// reporter keeps only proven loaded-code locations, never the supplied message
// or navigation event, and never retains the error across asynchronous work.
export const handleError: HandleClientError = (input) => {
	try { captureFlareRenderError(input); } catch { /* Error reporting must not throw. */ }
};
