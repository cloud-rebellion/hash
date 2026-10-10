<script lang="ts">
  import { page } from '$app/stores';
  import HtmlTemplateEditor from '$lib/components/HtmlTemplateEditor.svelte';
</script>
{#if $page.params.id}{#key $page.params.id}<HtmlTemplateEditor templateID={$page.params.id} />{/key}{/if}
