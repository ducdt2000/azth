export default defineNuxtConfig({
  devtools: { enabled: true },

  // Modules
  modules: [
    "@nuxt/ui",
    "@pinia/nuxt",
    "@vueuse/nuxt",
    "@nuxtjs/color-mode",
    "@nuxtjs/google-fonts",
    "@nuxt/image",
    "@nuxt/icon",
    "@nuxtjs/tailwindcss",
  ],

  // UI Configuration
  ui: {
    global: true,
  },

  // Color mode configuration
  colorMode: {
    preference: "system",
    fallback: "light",
    hid: "nuxt-color-mode-script",
    globalName: "__NUXT_COLOR_MODE__",
    componentName: "ColorScheme",
    classPrefix: "",
    classSuffix: "",
    storageKey: "azth-color-mode",
  },

  // Google Fonts
  googleFonts: {
    families: {
      Inter: [300, 400, 500, 600, 700, 800, 900],
    },
    display: "swap",
    preload: true,
  },

  // Image configuration
  image: {
    quality: 80,
    format: ["webp"],
  },

  // CSS
  css: ["~/assets/css/main.css"],

  // Runtime config
  runtimeConfig: {
    // Private keys (only available on server-side)
    jwtSecret: process.env.JWT_SECRET,

    // Public keys (exposed to client-side)
    public: {
      apiBaseUrl:
        process.env.NUXT_PUBLIC_API_BASE_URL || "http://localhost:8080",
      oidcIssuer:
        process.env.NUXT_PUBLIC_OIDC_ISSUER || "http://localhost:8080",
      oidcClientId: process.env.NUXT_PUBLIC_OIDC_CLIENT_ID || "azth-frontend",
      appName: "AZTH",
      appVersion: "1.0.0",
    },
  },

  // App configuration
  app: {
    head: {
      title: "AZTH - Multi-Tenant SSO & OIDC Server",
      titleTemplate: "%s | AZTH",
      meta: [
        { charset: "utf-8" },
        { name: "viewport", content: "width=device-width, initial-scale=1" },
        {
          name: "description",
          content: "Multi-tenant SSO and OIDC server with user management",
        },
        { name: "theme-color", content: "#3b82f6" },
      ],
      link: [{ rel: "icon", type: "image/x-icon", href: "/favicon.ico" }],
    },
  },

  // Build configuration
  build: {
    transpile: ["@headlessui/vue"],
  },

  // Nitro configuration
  nitro: {
    experimental: {
      wasm: true,
    },
  },

  // TypeScript configuration
  typescript: {
    strict: true,
    typeCheck: true,
  },

  // Development configuration
  devServer: {
    port: 3000,
    host: "0.0.0.0",
  },

  // SSR configuration
  ssr: true,

  // Experimental features
  experimental: {
    payloadExtraction: false,
    renderJsonPayloads: true,
  },

  // Vite configuration
  vite: {
    optimizeDeps: {
      include: ["jwt-decode", "qrcode"],
    },
  },
});
