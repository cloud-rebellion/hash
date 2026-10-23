<script lang="ts">
 import { page } from '$app/stores';
 import NoticeReader from '$lib/components/NoticeReader.svelte';
 const noticeID = $derived($page.params.id);
</script>
<svelte:head><meta name="robots" content="noindex,nofollow" /><meta name="referrer" content="no-referrer" /></svelte:head>
{#if noticeID}
 {#key noticeID}<NoticeReader {noticeID} />{/key}
{:else}
 <main class="min-h-screen bg-bg px-4 py-8"><p role="alert">This notice could not be opened. Open the original email link again or ask the sender for access.</p></main>
{/if}
