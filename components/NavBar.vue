<script setup lang="ts">
const props = defineProps({
  Open: Boolean,
  Mobile: Boolean
})
import ContactBtn from './ContactBtn.vue';
const emits = defineEmits(['closeMenu'])
</script>

<template>

    

  

  <nav v-if="Mobile != true" class="flex select-none font-sans text-base font-medium max-sm:hidden pr-4 textPrimaryColor items-center">
    <NuxtLink  class="p-4 hover:animate-jump" to="/">Home</NuxtLink >
    <NuxtLink  class="p-4 hover:animate-jump" to="/#portfolio">Portfolio</NuxtLink >
    <!-- <NuxtLink  class="p-4 hover:animate-jump" to="/hosting">Hosting</NuxtLink > -->
    <NuxtLink  class="p-4 hover:animate-jump" to="/about">About</NuxtLink >
    <ContactBtn />
  </nav>

  <nav
    v-if="Mobile != false && Open == false"
    class="animate-fadeout absolute top-16 w-full secondBackgroundColor font-sans text-base font-medium textSecondaryColor z-10"
  >
    <NuxtLink  class="block w-full p-4 text-center" to="/">Home</NuxtLink >
    <NuxtLink  class="block w-full p-4 text-center" to="/#portfolio">Portfolio</NuxtLink >
    <!-- <NuxtLink  class="block w-full p-4 text-center" to="/hosting">Hosting</NuxtLink > -->
    <NuxtLink  class="block w-full p-4 text-center" to="/about">About</NuxtLink >
  </nav>

  <nav
    v-else-if="Mobile != false && Open == true"
    class="animate-fadein animate-duration-500 absolute top-16 block w-full overflow-hidden secondBackgroundColor font-sans text-base font-medium sm:hidden z-10 "
  >
    <NuxtLink 
      class="block w-full p-4 text-center hover:animate-jump"
      @click="$emit('closeMenu')"
      to="/"
      >Home</NuxtLink 
    >
    <NuxtLink 
      class="block w-full p-4 text-center hover:animate-jump"
      @click="$emit('closeMenu')"
      to="/#portfolio"
      >Portfolio</NuxtLink 
    >
    <!-- <NuxtLink 
      class="block w-full p-4 text-center hover:animate-jump"
      @click="$emit('closeMenu')"
      to="/hosting"
      >Hosting</NuxtLink 
    > -->
    <NuxtLink 
      class="block w-full p-4 text-center hover:animate-jump"
      @click="$emit('closeMenu')"
      to="/about"
      >About</NuxtLink 
    >
  </nav>

  <nav
    v-else
    class="absolute hidden w-full overflow-hidden secondBackgroundColor font-sans text-base font-medium sm:hidden z-10"
  >
    <NuxtLink 
      class="block w-full p-4 text-center hover:animate-jump"
      @click="$emit('closeMenu')"
      to="/"
      >Home</NuxtLink 
    >
    <NuxtLink 
      class="block w-full p-4 text-center hover:animate-jump"
      @click="$emit('closeMenu')"
      to="/#portfolio"
      >Portfolio</NuxtLink 
    >
    <!-- <NuxtLink 
      class="block w-full p-4 text-center hover:animate-jump"
      @click="$emit('closeMenu')"
      to="/hosting"
      >Hosting</NuxtLink 
    > -->
    <NuxtLink 
      class="block w-full p-4 text-center hover:animate-jump"
      @click="$emit('closeMenu')"
      to="/about"
      >About</NuxtLink 
    >
  </nav>
  <div v-if="Mobile != false && Open == true" class="fixed w-full h-full bg-black/40 animate-fadein left-0 bottom-0 top-[64px]" @click="$emit('closeMenu')"></div>
</template>
