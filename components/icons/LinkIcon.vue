<script setup lang="ts">
    const props = defineProps({
        Link: String
    })
</script>
<template>
    <div v-if="Link != ''">
        <a target="_blank" :href="props.Link"> 
            <svg class="h-8 w-8 textPrimaryColor hover:animate-jump"  width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">  <path stroke="none" d="M0 0h24v24H0z"/>  <path d="M11 7h-5a2 2 0 0 0 -2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2 -2v-5" />  <line x1="10" y1="14" x2="20" y2="4" />  <polyline points="15 4 20 4 20 9" /></svg>
        </a>
    </div>
   
    
</template>