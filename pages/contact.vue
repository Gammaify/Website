<script setup lang="ts">


  
</script>
<template>
    
    <div>
        <Head>
        <Title>Contact</Title>
    </Head>
        <h1>Contact</h1>

        <form>
            <div class="mb-4">
                <label>Your Name</label>
                <input type="text" id="name" name="name" required>
            </div>
            <div class="mb-4">
                <label>Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="mb-4">
                <label>Subject</label>
                <select name="subject" id="subject">
                    <option value="General">General</option>
                    <option value="Web Development">Web Development</option>
                    <option value="Web Hosting">Web Hosting</option>
                </select>
            </div>
            <div class="mb-4">
                <label>Message</label>
                <textarea name="message" id="message" required></textarea>
            </div>
            
            
        </form>
    </div>
    
</template>