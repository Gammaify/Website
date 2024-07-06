// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  devtools: { enabled: true },
  css: ['~/assets/main.css'],

  postcss: {
    plugins: {
      tailwindcss: {},
      autoprefixer: {},
    },
  },
  app: {
    pageTransition: { name: 'fade', mode: 'out-in' }
  },
  security: {
    headers: {
      contentSecurityPolicy: {
        
      }
    }
  },
  cron: {
    runOnInit: true,
    timeZone: 'Europe/London',
    jobsDir: 'cron'
  },
  modules: ['nuxt-security', 'nuxt-cron']
})