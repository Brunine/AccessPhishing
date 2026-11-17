/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          900: "#0b0f1a",
          800: "#111726",
          700: "#1b2233",
          600: "#2a3347",
        },
      },
    },
  },
  plugins: [],
};
