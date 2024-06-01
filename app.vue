<style>
.fade-enter-active,
.fade-leave-active {
  transition: all 0.4s;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

<template>
  <div>
    <Header />
      <NuxtPage />
    
  </div>
</template>

<script setup lang="ts">
  import Header from './components/Header.vue'

  useHead({
    meta: [
      {
        name: 'description', content: 'Gammaify creates high-quality websites, Shopify apps, and themes to elevate your online presence. We transform your vision into reality, empowering your business to thrive.'
      }
    ],
    titleTemplate: (titleChunk) => {
      return titleChunk ? `${titleChunk} - Gammaify` : 'Gammaify';
    },
    link: [{ rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }]
  })
</script>
