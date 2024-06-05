<script setup lang="ts">
    const { data: contacts } = await useFetch('/api/contact')

  
</script>
<template>
    
    <div>
        <Head>
        <Title>Contact</Title>
    </Head>
        <h1>Contact</h1>
        <p v-for="contact in contacts">
            {{ contact.first_name }}
        </p>
        <p>test123</p>
    </div>
    
</template>