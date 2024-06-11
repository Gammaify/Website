<script setup lang="ts">

import NavBar from '../components/NavBar.vue'
import MenuIcon from '../components/icons/MenuIcon.vue'
const isMenuOpen = useState<boolean | undefined>()

function OpenMenu() {
  if (isMenuOpen.value == true) {
    isMenuOpen.value = false
  } else if (isMenuOpen.value == false) {
    isMenuOpen.value = true
  } else {
    isMenuOpen.value = true
  }
}

function closeMenu() {
  isMenuOpen.value = false
}
</script>

<template>
  <div class="flex items-center justify-between backgroundColor textSecondaryColor max-md:w-full w-9/12 m-auto">
    <RouterLink to="/">
      <img
        class="ml-3 hover:animate-jump p-1"
        src="../assets/images/logo-white2.png"
        width="50"
        height="50"
        title="Gammaify Logo"
        alt="Gammaify Logo"
      />
    </RouterLink>
    <NavBar :Mobile="false" :Open="isMenuOpen" />
    <MenuIcon :Open="isMenuOpen" @click="OpenMenu" />
  </div>
  <NavBar :Mobile="true" :Open="isMenuOpen" @close-menu="closeMenu" />
</template>


