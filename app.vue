
<script setup lang="ts">
  import Header from './components/Header.vue'
  import Footer from './components/Footer.vue'

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


<template>
  <div class="flex flex-col min-h-screen">
    <Header />
    <div class="flex-1">
      <NuxtPage />
    </div>
      
    <Footer />
  </div>
</template>

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
