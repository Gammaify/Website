
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
  <div class="flex flex-col min-h-screen backgroundColor">
    <Header />
    <div class="flex-1 max-md:w-full w-9/12 m-auto p-4 textPrimaryColor">
      <NuxtPage />
    </div>
      
    <Footer />
  </div>
</template>

<style>
.textPrimaryColor{
  color: #E8F3F5;
}

.textSecondaryColor{
  color: #006241;
}

.backgroundColor{
  background-color: #006241;
}

.secondBackgroundColor{
  background-color: #90E2BA;
}

.borderColor{
  border-color: #90E2BA;
}

.primaryButton{
  background-color: #00BEFF;
  height: 35px;
  align-items: center;
  display: flex;
  margin-top: 10px;
  border-radius: 10px;
}

.fade-enter-active,
.fade-leave-active {
  transition: all 0.4s;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

</style>
