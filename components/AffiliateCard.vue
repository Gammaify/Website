<script setup lang="ts">

const props = defineProps({
   ImageURL: String,
   Name: String,
   WebsiteURL: String,
   Description: String
})
</script>
<template>
    <div class="flex mt-10 flex-wrap w-full">
        <img class="lg:w-1/3 w-full self-start sm:pr-4" :src="props.ImageURL" />
        <div class="w-full lg:w-2/3">
            <h2 class="text-2xl">{{ props.Name }}</h2>
            <div v-html="props.Description"></div>
            <div class="flex justify-center pt-4">
                <a :href="props.WebsiteURL" class="hover:animate-jump hover:cursor-pointer primaryButton p-4 ml-4 text-white font-medium">Visit Website</a>
            </div>
            
        </div>
        
    </div>
    
</template>