<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import { getMe } from '$lib/api/client';
  import { ui } from '$lib/staffPreferences';
  import ReminderPolicySettings from '$lib/components/ReminderPolicySettings.svelte';
  import HtmlTemplateEditor from '$lib/components/HtmlTemplateEditor.svelte';
  let canManage = $state(false), policyDirty = $state(false), policyBusy = $state(false), policyUnknown = $state(false);
  let disposed = false;
  onMount(() => { void getMe().then(me => { if(!disposed) canManage = me.role === 'owner' || me.role === 'sender'; }).catch(() => {}); return () => { disposed = true; }; });
  beforeNavigate(({cancel}) => { if(policyBusy || policyUnknown || (policyDirty && !window.confirm($ui('Discard unsaved reminder changes?')))) cancel(); });
</script>
{#if $page.params.id}{#key $page.params.id}<HtmlTemplateEditor templateID={$page.params.id} />{/key}{/if}

{#if $page.params.id && canManage}{#key $page.params.id}
  <div class="mx-auto max-w-6xl px-6 pb-10"><ReminderPolicySettings scope="template" id={$page.params.id}
    onStateChange={(state)=>{policyDirty=state.dirty;policyBusy=state.busy;policyUnknown=state.unconfirmed;}} /></div>
{/key}{/if}
