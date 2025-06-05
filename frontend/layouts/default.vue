<template>
  <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
    <!-- Navigation Header -->
    <header
      class="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700"
    >
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between items-center h-16">
          <!-- Logo -->
          <div class="flex items-center">
            <NuxtLink to="/" class="flex items-center space-x-2">
              <UIcon
                name="i-heroicons-shield-check-20-solid"
                class="w-8 h-8 text-blue-600"
              />
              <span class="text-xl font-bold text-gray-900 dark:text-white"
                >AZTH</span
              >
            </NuxtLink>
          </div>

          <!-- Navigation Menu -->
          <nav class="hidden md:flex items-center space-x-8">
            <NuxtLink
              v-for="item in navigation"
              :key="item.name"
              :to="item.href"
              class="text-gray-600 hover:text-gray-900 dark:text-gray-300 dark:hover:text-white px-3 py-2 rounded-md text-sm font-medium transition-colors"
              active-class="text-blue-600 dark:text-blue-400"
            >
              {{ item.name }}
            </NuxtLink>
          </nav>

          <!-- User Menu -->
          <div class="flex items-center space-x-4">
            <!-- Color Mode Toggle -->
            <UButton
              variant="ghost"
              color="gray"
              size="sm"
              square
              @click="toggleColorMode"
            >
              <UIcon
                :name="
                  colorMode.preference === 'dark'
                    ? 'i-heroicons-sun-20-solid'
                    : 'i-heroicons-moon-20-solid'
                "
                class="w-5 h-5"
              />
            </UButton>

            <!-- User Avatar/Login -->
            <div v-if="user">
              <UDropdown :items="userMenuItems">
                <UButton
                  variant="ghost"
                  color="gray"
                  size="sm"
                  :label="user.name"
                  trailing-icon="i-heroicons-chevron-down-20-solid"
                />

                <template #avatar>
                  <UAvatar :src="user.avatar" :alt="user.name" size="sm" />
                </template>
              </UDropdown>
            </div>
            <div v-else class="flex items-center space-x-2">
              <UButton to="/auth/login" variant="ghost" color="gray" size="sm">
                Sign In
              </UButton>
              <UButton to="/auth/register" size="sm"> Sign Up </UButton>
            </div>

            <!-- Mobile menu button -->
            <UButton
              variant="ghost"
              color="gray"
              size="sm"
              square
              class="md:hidden"
              @click="mobileMenuOpen = !mobileMenuOpen"
            >
              <UIcon name="i-heroicons-bars-3-20-solid" class="w-6 h-6" />
            </UButton>
          </div>
        </div>

        <!-- Mobile Navigation -->
        <div v-show="mobileMenuOpen" class="md:hidden">
          <div class="px-2 pt-2 pb-3 space-y-1 sm:px-3">
            <NuxtLink
              v-for="item in navigation"
              :key="item.name"
              :to="item.href"
              class="text-gray-600 hover:text-gray-900 dark:text-gray-300 dark:hover:text-white block px-3 py-2 rounded-md text-base font-medium"
              active-class="text-blue-600 dark:text-blue-400"
              @click="mobileMenuOpen = false"
            >
              {{ item.name }}
            </NuxtLink>
          </div>
        </div>
      </div>
    </header>

    <!-- Main Content -->
    <main class="flex-1">
      <slot />
    </main>

    <!-- Footer -->
    <footer
      class="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700"
    >
      <div class="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <div class="flex flex-col md:flex-row justify-between items-center">
          <div class="flex items-center space-x-2 mb-4 md:mb-0">
            <UIcon
              name="i-heroicons-shield-check-20-solid"
              class="w-6 h-6 text-blue-600"
            />
            <span class="text-sm text-gray-600 dark:text-gray-400">
              © 2024 AZTH. All rights reserved.
            </span>
          </div>
          <div class="flex space-x-6">
            <NuxtLink
              to="/privacy"
              class="text-sm text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
            >
              Privacy Policy
            </NuxtLink>
            <NuxtLink
              to="/terms"
              class="text-sm text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
            >
              Terms of Service
            </NuxtLink>
            <NuxtLink
              to="/support"
              class="text-sm text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
            >
              Support
            </NuxtLink>
          </div>
        </div>
      </div>
    </footer>
  </div>
</template>

<script setup lang="ts">
const colorMode = useColorMode();
const { user, logout } = useAuth();

const mobileMenuOpen = ref(false);

const navigation = [
  { name: "Dashboard", href: "/dashboard" },
  { name: "Users", href: "/users" },
  { name: "Tenants", href: "/tenants" },
  { name: "Applications", href: "/applications" },
  { name: "Audit Logs", href: "/audit" },
];

const userMenuItems = computed(() => [
  [
    {
      label: "Profile",
      icon: "i-heroicons-user-circle-20-solid",
      click: () => navigateTo("/profile"),
    },
    {
      label: "Settings",
      icon: "i-heroicons-cog-6-tooth-20-solid",
      click: () => navigateTo("/settings"),
    },
  ],
  [
    {
      label: "Sign Out",
      icon: "i-heroicons-arrow-right-on-rectangle-20-solid",
      click: logout,
    },
  ],
]);

const toggleColorMode = () => {
  colorMode.preference = colorMode.value === "dark" ? "light" : "dark";
};

// Auto-hide mobile menu on route change
watch(
  () => useRoute().path,
  () => {
    mobileMenuOpen.value = false;
  }
);
</script>
