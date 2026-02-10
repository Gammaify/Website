<script setup lang="ts">
 import PortfolioCard from '~/components/PortfolioCard.vue';
</script>


<template>
    
    <div>
        <Head>
            <Title>Home</Title>
        </Head>
        <div class="mx-auto w-4/5 md:w-3/5 lg:w-3/5 xl:w-1/3">
            <img class="rounded-full borderColor border-4" src="/images/profile.jpg" alt="Picture of Me">
            <h1 class="pt-4 text-center text-xl">Hey there! My name's Oliver Smith, and welcome to Gammaify, your one-stop shop for all things website gamification!</h1>
        </div>
        <h2 class="text-center text-3xl p-5 mt-5 border-solid border-t-2 borderColor" id="portfolio">Portfolio</h2>
        <div class="grid lg:grid-cols-3 md:grid-cols-2 gap-4">
            <PortfolioCard ImageURL="/images/gingerfoxSite.png" ProjectName="Ginger Fox" GitHubLink="https://github.com/Gammaify/GingerFoxTheme" WebsiteLink="https://www.gingerfox.co.uk" />
            <PortfolioCard ImageURL="/images/traitorsDigitalGame.png" ProjectName="Traitors Digital Game" GitHubLink="https://github.com/Gammaify/TraitorsDigitalGame" WebsiteLink="https://gingerfoxlink.gingerfox.co.uk/link?h=cUVMK2NPaStVOVE9" />
            <PortfolioCard ImageURL="/images/catchphraseMicrosite.png" ProjectName="Catchphrase Micro-site" GitHubLink="https://github.com/Gammaify/CatchphraseMicrosite" WebsiteLink="https://www.catchphrasecardgame.com/" />
            <PortfolioCard ImageURL="/images/popmasterMicrosite.png" ProjectName="Popmaster Micro-site" GitHubLink="https://github.com/Gammaify/PopmasterMicrosite" WebsiteLink="https://www.popmastergame.co.uk/board-game" />
            <PortfolioCard ImageURL="/images/TraitorsMicrosite.png" ProjectName="Traitors Micro-site" GitHubLink="https://github.com/Gammaify/TraitorsMicrosite" WebsiteLink="https://www.thetraitorscardgame.co.uk/" />
            <PortfolioCard ImageURL="/images/tapSite.png" ProjectName="The Admin Practice" GitHubLink="https://github.com/Gammaify/TheAdminPractice" WebsiteLink="" />
            
        </div>
        
    </div>
    
</template>

