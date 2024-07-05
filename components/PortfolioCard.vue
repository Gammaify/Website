<script setup lang="ts">

 const props = defineProps({
    ImageURL: String,
    GitHubLink: String,
    ProjectName: String,
    WebsiteLink: String
 })
 import Github from './icons/Github.vue';
 import LinkIcon from './icons/LinkIcon.vue';

</script>

<template>
    <div class="border-solid border-2 borderColor rounded p-2">
        <a v-if="props.WebsiteLink != ''" target="_blank" :href="props.WebsiteLink">
            <img :src="props.ImageURL" />
        </a>
        <img v-else :src="props.ImageURL" />
        
        <h4 class="p-2 text-center text-xl lg:text-base">{{ props.ProjectName }}</h4>
        <div class="flex justify-between">
            <LinkIcon :Link="props.WebsiteLink" />
            <Github :Link="props.GitHubLink"/>
        </div>
        
    </div>
</template>