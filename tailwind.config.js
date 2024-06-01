/** @type {import('tailwindcss').Config} */
export default {
  content: [
  "./components/**/*.{js,vue,ts}",
  "./layouts/**/*.vue",
  "./pages/**/*.vue",
  "./plugins/**/*.{js,ts}",
  "./app.vue",
  "./error.vue",
],
  theme: {
    extend: {
      keyframes: {
        fadeout: {
          '0%': { opacity: 1, visibility: 'visible' },
          '100%': { opacity: 0, visibility: 'hidden' }
        },
        fadein: {
          '0%': { opacity: 0, visibility: 'hidden' },
          '100%': { opacity: 1, visibility: 'visible' }
        }
      },
      animation: {
        fadeout: 'fadeout 0.5s ease-in-out normal forwards',
        fadein: 'fadein 0.5s ease-in-out normal forwards'
      }
    },
  },
  plugins: [require('tailwindcss-animated')],
}

