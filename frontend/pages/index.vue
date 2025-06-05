<template>
  <div>
    <!-- Hero Section -->
    <section
      class="relative bg-gradient-to-br from-blue-50 via-white to-purple-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 overflow-hidden"
    >
      <div class="absolute inset-0 bg-white/30 dark:bg-gray-900/30"></div>
      <div
        class="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 lg:py-32"
      >
        <div class="grid lg:grid-cols-2 gap-12 items-center">
          <div class="space-y-8">
            <div class="space-y-4">
              <h1
                class="text-4xl lg:text-6xl font-bold text-gray-900 dark:text-white leading-tight"
              >
                Enterprise
                <span class="gradient-text">SSO & OIDC</span>
                Platform
              </h1>
              <p
                class="text-xl text-gray-600 dark:text-gray-300 leading-relaxed"
              >
                Secure, scalable, and simple identity management for modern
                applications. Multi-tenant architecture with comprehensive user
                management and audit capabilities.
              </p>
            </div>

            <div class="flex flex-col sm:flex-row gap-4">
              <UButton to="/auth/register" size="lg" class="justify-center">
                Get Started Free
                <UIcon
                  name="i-heroicons-arrow-right-20-solid"
                  class="w-5 h-5 ml-2"
                />
              </UButton>
              <UButton
                to="/demo"
                variant="outline"
                size="lg"
                class="justify-center"
              >
                View Demo
                <UIcon name="i-heroicons-play-20-solid" class="w-5 h-5 ml-2" />
              </UButton>
            </div>

            <div
              class="flex items-center space-x-6 text-sm text-gray-600 dark:text-gray-400"
            >
              <div class="flex items-center space-x-2">
                <UIcon
                  name="i-heroicons-check-circle-20-solid"
                  class="w-5 h-5 text-green-500"
                />
                <span>30-day free trial</span>
              </div>
              <div class="flex items-center space-x-2">
                <UIcon
                  name="i-heroicons-check-circle-20-solid"
                  class="w-5 h-5 text-green-500"
                />
                <span>No credit card required</span>
              </div>
            </div>
          </div>

          <div class="relative">
            <div
              class="relative z-10 bg-white dark:bg-gray-800 rounded-2xl shadow-2xl p-8 border border-gray-200 dark:border-gray-700"
            >
              <div class="space-y-6">
                <div class="flex items-center justify-between">
                  <h3
                    class="text-lg font-semibold text-gray-900 dark:text-white"
                  >
                    Login to Your App
                  </h3>
                  <div
                    class="w-3 h-3 bg-green-500 rounded-full animate-pulse"
                  ></div>
                </div>

                <div class="space-y-4">
                  <div>
                    <label
                      class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
                      >Email</label
                    >
                    <div
                      class="w-full h-10 bg-gray-100 dark:bg-gray-700 rounded-lg animate-pulse"
                    ></div>
                  </div>
                  <div>
                    <label
                      class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
                      >Password</label
                    >
                    <div
                      class="w-full h-10 bg-gray-100 dark:bg-gray-700 rounded-lg animate-pulse"
                    ></div>
                  </div>
                  <div
                    class="w-full h-10 bg-blue-500 rounded-lg animate-pulse"
                  ></div>
                </div>

                <div class="text-center">
                  <div class="text-sm text-gray-500 dark:text-gray-400 mb-4">
                    Or continue with
                  </div>
                  <div class="flex justify-center space-x-4">
                    <div
                      class="w-10 h-10 bg-gray-100 dark:bg-gray-700 rounded-lg animate-pulse"
                    ></div>
                    <div
                      class="w-10 h-10 bg-gray-100 dark:bg-gray-700 rounded-lg animate-pulse"
                    ></div>
                    <div
                      class="w-10 h-10 bg-gray-100 dark:bg-gray-700 rounded-lg animate-pulse"
                    ></div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Floating elements -->
            <div
              class="absolute -top-4 -right-4 w-20 h-20 bg-blue-500/20 rounded-full blur-xl"
            ></div>
            <div
              class="absolute -bottom-4 -left-4 w-16 h-16 bg-purple-500/20 rounded-full blur-xl"
            ></div>
          </div>
        </div>
      </div>
    </section>

    <!-- Features Section -->
    <section class="py-24 bg-white dark:bg-gray-800">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2
            class="text-3xl lg:text-4xl font-bold text-gray-900 dark:text-white mb-4"
          >
            Everything you need for identity management
          </h2>
          <p class="text-xl text-gray-600 dark:text-gray-300 max-w-3xl mx-auto">
            Built for developers, designed for scale. Our platform provides
            enterprise-grade security with developer-friendly APIs.
          </p>
        </div>

        <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
          <div
            v-for="feature in features"
            :key="feature.title"
            class="p-6 rounded-xl border border-gray-200 dark:border-gray-700 card-hover"
          >
            <div
              class="w-12 h-12 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center mb-4"
            >
              <UIcon
                :name="feature.icon"
                class="w-6 h-6 text-blue-600 dark:text-blue-400"
              />
            </div>
            <h3
              class="text-xl font-semibold text-gray-900 dark:text-white mb-2"
            >
              {{ feature.title }}
            </h3>
            <p class="text-gray-600 dark:text-gray-300">
              {{ feature.description }}
            </p>
          </div>
        </div>
      </div>
    </section>

    <!-- Stats Section -->
    <section class="py-16 bg-gray-50 dark:bg-gray-900">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-8">
          <div v-for="stat in stats" :key="stat.label" class="text-center">
            <div
              class="text-3xl lg:text-4xl font-bold text-blue-600 dark:text-blue-400 mb-2"
            >
              {{ stat.value }}
            </div>
            <div class="text-sm text-gray-600 dark:text-gray-400">
              {{ stat.label }}
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- CTA Section -->
    <section class="py-24 bg-gradient-to-r from-blue-600 to-purple-600">
      <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <h2 class="text-3xl lg:text-4xl font-bold text-white mb-4">
          Ready to secure your applications?
        </h2>
        <p class="text-xl text-blue-100 mb-8 max-w-2xl mx-auto">
          Join thousands of developers who trust AZTH for their identity
          management needs. Start your free trial today.
        </p>
        <div class="flex flex-col sm:flex-row gap-4 justify-center">
          <UButton
            to="/auth/register"
            size="lg"
            color="white"
            class="justify-center"
          >
            Start Free Trial
            <UIcon
              name="i-heroicons-arrow-right-20-solid"
              class="w-5 h-5 ml-2"
            />
          </UButton>
          <UButton
            to="/contact"
            variant="outline"
            size="lg"
            color="white"
            class="justify-center"
          >
            Contact Sales
          </UButton>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
// SEO Meta
useHead({
  title: "Enterprise SSO & OIDC Platform",
  meta: [
    {
      name: "description",
      content:
        "Secure, scalable, and simple identity management for modern applications. Multi-tenant architecture with comprehensive user management.",
    },
    {
      property: "og:title",
      content: "AZTH - Enterprise SSO & OIDC Platform",
    },
    {
      property: "og:description",
      content:
        "Secure, scalable, and simple identity management for modern applications.",
    },
    {
      property: "og:type",
      content: "website",
    },
  ],
});

const features = [
  {
    title: "OpenID Connect",
    description:
      "Full OIDC server implementation with OAuth 2.0 support for seamless integration.",
    icon: "i-heroicons-shield-check-20-solid",
  },
  {
    title: "Multi-Tenant",
    description:
      "Complete tenant isolation with custom branding and configuration per organization.",
    icon: "i-heroicons-building-office-2-20-solid",
  },
  {
    title: "User Management",
    description:
      "Comprehensive user lifecycle management with roles, permissions, and audit trails.",
    icon: "i-heroicons-users-20-solid",
  },
  {
    title: "Security First",
    description:
      "Enterprise-grade security with MFA, session management, and security policies.",
    icon: "i-heroicons-lock-closed-20-solid",
  },
  {
    title: "Developer APIs",
    description:
      "RESTful APIs with comprehensive documentation and SDKs for easy integration.",
    icon: "i-heroicons-code-bracket-20-solid",
  },
  {
    title: "Analytics & Audit",
    description:
      "Detailed audit logs and analytics for compliance and security monitoring.",
    icon: "i-heroicons-chart-bar-20-solid",
  },
];

const stats = [
  { value: "99.9%", label: "Uptime SLA" },
  { value: "10M+", label: "API Calls/Month" },
  { value: "<100ms", label: "Avg Response Time" },
  { value: "24/7", label: "Support Available" },
];
</script>
