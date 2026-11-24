/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0B1220",
        surface: "#F7F8FA",
        line: "#E6E8EC",
        signal: {
          DEFAULT: "#1E6F5C",   // safe - deep teal-green
          soft: "#E7F3EF",
        },
        caution: {
          DEFAULT: "#B7791F",  // suspicious - amber
          soft: "#FBF1DE",
        },
        danger: {
          DEFAULT: "#B42318",  // malicious - deep red
          soft: "#FBEAE8",
        },
        brand: {
          DEFAULT: "#1C3AA9",  // primary blue accent, used sparingly
          dark: "#13297A",
        },
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        body: ["'Inter'", "sans-serif"],
        mono: ["'JetBrains Mono'", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(11,18,32,0.04), 0 1px 12px rgba(11,18,32,0.04)",
      },
    },
  },
  plugins: [],
}
