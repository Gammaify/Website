<script setup lang="ts">
const emits = defineEmits(['closeMenu'])
import ContactPopup from './ContactPopup.vue';
const isContactUsOpen = useState<boolean | undefined>()
function OpenContactUs(){
  if(isContactUsOpen.value == true){
    isContactUsOpen.value = false;
  }
  else if(isContactUsOpen.value == false){
    isContactUsOpen.value = true;
  }
  else{
    isContactUsOpen.value = true;
  }
}

function CloseContactUs(){
  isContactUsOpen.value = false;
}
</script>

<template>
    <div class="hover:animate-jump hover:cursor-pointer primaryButton p-4 ml-4 text-white font-medium" @click="OpenContactUs(); $emit('closeMenu')">Contact3</div >
    <ContactPopup :Open="isContactUsOpen" @close-contact-form="CloseContactUs" />
</template>