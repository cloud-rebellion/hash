<script lang="ts">
 import {page} from '$app/stores';
 import CompletedPackageDownloads from '$lib/components/CompletedPackageDownloads.svelte';
</script>
<svelte:head><title>Completed contract · Hash</title><meta name="robots" content="noindex,nofollow"/><meta name="referrer" content="no-referrer"/></svelte:head>
{#key $page.params.token}<CompletedPackageDownloads token={$page.params.token??''}/>{/key}
