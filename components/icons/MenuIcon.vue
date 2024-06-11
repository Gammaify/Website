<template>
  <div class="p-4 sm:hidden">
    <svg
      v-if="Open == false"
      class="h-8 w-8 textPrimaryColor hover:cursor-pointer"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        stroke-width="2"
        d="M4 6h16M4 12h16M4 18h16"
      />
    </svg>

    <svg
      v-else-if="Open == true"
      class="h-8 w-8 textPrimaryColor hover:cursor-pointer"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
    >
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>

    <svg
      v-else
      class="h-8 w-8 textPrimaryColor hover:cursor-pointer"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        stroke-width="2"
        d="M4 6h16M4 12h16M4 18h16"
      />
    </svg>
  </div>
</template>

<script setup lang="ts">
const props = defineProps({
  Open: Boolean
})
</script>
