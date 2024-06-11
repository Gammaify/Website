<script setup lang="ts">
    import Twitter  from './icons/Twitter.vue';
    import Facebook from './icons/Facebook.vue';
    import Instagram from './icons/Instagram.vue';
    import GitHub from './icons/Github.vue';


    const currentYear = new Date().getFullYear();

</script>


<template>
    <div class="sm:flex justify-between p-4 max-sm:block max-sm:m-auto backgroundColor items-center w-9/12 m-auto">
        <!-- <NuxtLink to="/">
            <img class="m-auto max-sm:mb-4 hover:animate-jump" src="../assets/images/logo-white.png" width="50" height="50" alt="Gammaify Logo">
        </NuxtLink> -->
        <p class="text-white max-sm:text-center max-sm:mb-4">Copyright &copy;{{ currentYear }} Gammaify</p>
        <div class="flex justify-evenly items-center w-48 max-sm:m-auto">
            <Twitter />
            <Facebook />
            <Instagram />
            <GitHub />
        </div>
    </div>
    
</template>