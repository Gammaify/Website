<script setup lang="ts">
 const props = defineProps({
    Open: Boolean
 })

const emits = defineEmits(['closeContactForm'])

interface FormData {
    name: string,
    email: string,
    message: string
}

const formData = ref<FormData>({
    name: '',
    email: '',
    message: ''
})


const message = useState<string>();
const nameError = useState<string>();
const emailError = useState<string>();
const messageError = useState<string>();



function validateData(data: FormData) {
    var sendMessage = true;
    var nameRegex = /^[a-zA-Z\s]*$/;
        if (!nameRegex.test(data.name) || data.name == ''){
            nameError.value = 'Please enter a valid name.'
            sendMessage = false;
        }
        else{
            nameError.value = '';
        }
        

        var emailRegex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
        if (!emailRegex.test(data.email) || data.email == ''){
            emailError.value = 'Please enter a valid email.'
            sendMessage = false;
        }
        else{
            emailError.value = '';
           
        }

        var messageRegex = /^(?=.*[A-Z0-9])[()£?\n|@&-;\w.,!"'\/ ]+$/i;
        if (!messageRegex.test(data.message) || data.message == ''){
            messageError.value = 'Please use only english words and punctuation.'
            sendMessage = false;
        }
        else{
            messageError.value = '';
        
        }

        return sendMessage
}

const submitForm = async () => {
    try{
        message.value = '';
        
        

         if (validateData(formData.value)){
            const res = await $fetch('/api/contact', {
                method: 'POST',
                body: JSON.stringify(formData.value),
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            
            if (res == 'success'){
                message.value = 'Your message has been sent. I will get back to you as soon as possible!'
                formData.value.name = '';
                formData.value.email = '';
                formData.value.message = '';
            }
            else{
                message.value = 'Something went wrong. Please try again.'
            }
         }
        
    }
    catch (err){
        message.value = 'Something went wrong. Please try again.'
        console.log(err)
    }
    
}

const closeForm = () => {
    emits('closeContactForm')
    message.value = '';
    nameError.value = '';
    emailError.value = '';
    messageError.value = '';   
}


</script>

<template>
    <div v-if="Open == true" >
        <div  class="fixed mx-auto my-auto inset-x-0 w-9/12 h-min inset-y-0 max-md:w-11/12 secondBackgroundColor rounded p-4 z-10 animate-fadein">
            <div class="absolute right-3" @click="closeForm">
                <svg
                class="h-8 w-8 textSecondaryColor hover:cursor-pointer"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                >
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
            </div>
            <h4 class="text-center textSecondaryColor text-3xl font-bold">Contact Me</h4>
            <form @submit.prevent="submitForm" id="contactForm">
                <p class="textSecondaryColor pb-2 pt-2 text-center font-bold">{{ message }}</p>
                <div class="textSecondaryColor pb-2 w-full">
                    <label class="w-full block text-xl font-bold pb-1">Your Name</label>
                    <input v-model="formData.name" class="rounded p-1 w-full" type="text" id="name" name="name" />
                    <p>{{ nameError }}</p>
                </div>
                <div class="textSecondaryColor pb-2 w-full">
                    <label class="w-full block text-xl font-bold pb-1">Email</label>
                    <input v-model="formData.email" class="rounded p-1 w-full" type="email" id="email" name="email" />
                    <p>{{ emailError }}</p>
                </div>
                <div class="textSecondaryColor pb-2 w-full">
                    <label class="w-full block text-xl font-bold pb-1">Message</label>
                    <textarea v-model="formData.message" rows="4" class="rounded p-1 w-full" type="text" id="message" name="message"></textarea>
                    <p>{{ messageError }}</p>
                </div>
                <button type="submit" class="primaryButton px-7 text-white font-medium mx-auto hover:animate-jump">Send</button>
            </form>
        </div>
    </div>
    <div v-if="Open == true" class="fixed w-full h-full bg-black/40 animate-fadein left-0 bottom-0" @click="closeForm"></div>
</template>