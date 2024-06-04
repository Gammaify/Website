<script setup lang="ts">
    import Twitter  from './icons/Twitter.vue';
    import Facebook from './icons/Facebook.vue';
    import Instagram from './icons/Instagram.vue';
    import GitHub from './icons/GitHub.vue';


    const currentYear = new Date().getFullYear();

</script>


<template>
    <div class="sm:flex justify-between p-4 max-sm:block max-sm:m-auto border-solid border-b-2 border-green-600 w-full bg-green-200">
        <NuxtLink to="/">
            <img class="m-auto max-sm:mb-4 hover:animate-jump" src="../assets/images/logo-green.png" width="50" height="50" alt="Gammaify Logo">
        </NuxtLink>
        <div class="flex justify-evenly items-center w-48 max-sm:m-auto">
            <Twitter />
            <Facebook />
            <Instagram />
            <GitHub />
        </div>
    </div>
    <div class="flex justify-center p-2 bg-green-200">
        <p class="text-green-600">Copyright &copy;{{ currentYear }} Gammaify</p>
    </div>
</template>