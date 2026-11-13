/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', '"Consolas"', 'monospace'],
      },
      colors: {
        'cyber-bg': '#0b0f14',
        'cyber-green': '#00ff88',
        'cyber-cyan': 'rgb(0 255 255)',
        'cyber-red': '#ff4757',
      },
      boxShadow: {
        'neon': '0 0 5px #00ff88, 0 0 20px rgba(0, 255, 136, 0.3)',
        'neon-sm': '0 0 3px rgba(0, 255, 136, 0.5)',
      },
      animation: {
        'blink': 'blink 1s step-end infinite',
        'fade-in': 'fadeIn 0.3s ease-out',
        'scanline': 'scanline 8s linear infinite',
      },
      keyframes: {
        blink: {
          '50%': { opacity: '0' },
        },
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
      },
    },
  },
  plugins: [],
};
