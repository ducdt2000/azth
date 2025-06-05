interface User {
  id: string;
  email: string;
  name: string;
  avatar?: string;
  roles: string[];
  tenant?: {
    id: string;
    name: string;
    slug: string;
  };
}

interface LoginCredentials {
  email: string;
  password: string;
  rememberMe?: boolean;
}

interface RegisterData {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  tenantName?: string;
}

interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
}

const authState = reactive<AuthState>({
  user: null,
  accessToken: null,
  refreshToken: null,
  isLoading: false,
  isAuthenticated: false,
});

export const useAuth = () => {
  const { $fetch } = useNuxtApp();
  const config = useRuntimeConfig();
  const router = useRouter();

  // Check if user is authenticated
  const checkAuth = async () => {
    authState.isLoading = true;
    try {
      const token = useCookie("access_token");
      if (!token.value) {
        authState.isAuthenticated = false;
        return false;
      }

      // Verify token and get user info
      const response = await $fetch<{ user: User }>("/api/v1/auth/me", {
        baseURL: config.public.apiBaseUrl,
        headers: {
          Authorization: `Bearer ${token.value}`,
        },
      });

      authState.user = response.user;
      authState.accessToken = token.value;
      authState.isAuthenticated = true;
      return true;
    } catch (error) {
      console.error("Auth check failed:", error);
      await logout();
      return false;
    } finally {
      authState.isLoading = false;
    }
  };

  // Login with email and password
  const login = async (credentials: LoginCredentials) => {
    authState.isLoading = true;
    try {
      const response = await $fetch<{
        user: User;
        accessToken: string;
        refreshToken: string;
      }>("/api/v1/auth/login", {
        baseURL: config.public.apiBaseUrl,
        method: "POST",
        body: credentials,
      });

      // Store tokens in cookies
      const accessTokenCookie = useCookie("access_token", {
        maxAge: 60 * 60 * 24 * 7, // 7 days
        secure: true,
        sameSite: "strict",
      });
      const refreshTokenCookie = useCookie("refresh_token", {
        maxAge: 60 * 60 * 24 * 30, // 30 days
        secure: true,
        sameSite: "strict",
      });

      accessTokenCookie.value = response.accessToken;
      refreshTokenCookie.value = response.refreshToken;

      authState.user = response.user;
      authState.accessToken = response.accessToken;
      authState.refreshToken = response.refreshToken;
      authState.isAuthenticated = true;

      await router.push("/dashboard");
      return response;
    } catch (error) {
      console.error("Login failed:", error);
      throw error;
    } finally {
      authState.isLoading = false;
    }
  };

  // Register new user
  const register = async (data: RegisterData) => {
    authState.isLoading = true;
    try {
      const response = await $fetch<{
        user: User;
        message: string;
      }>("/api/v1/auth/register", {
        baseURL: config.public.apiBaseUrl,
        method: "POST",
        body: data,
      });

      // Redirect to login with success message
      await router.push({
        path: "/auth/login",
        query: { message: "Registration successful. Please login." },
      });

      return response;
    } catch (error) {
      console.error("Registration failed:", error);
      throw error;
    } finally {
      authState.isLoading = false;
    }
  };

  // Logout user
  const logout = async () => {
    try {
      // Call logout endpoint if token exists
      if (authState.accessToken) {
        await $fetch("/api/v1/auth/logout", {
          baseURL: config.public.apiBaseUrl,
          method: "POST",
          headers: {
            Authorization: `Bearer ${authState.accessToken}`,
          },
        });
      }
    } catch (error) {
      console.error("Logout API call failed:", error);
    } finally {
      // Clear state and cookies regardless of API call result
      authState.user = null;
      authState.accessToken = null;
      authState.refreshToken = null;
      authState.isAuthenticated = false;

      // Clear cookies
      const accessTokenCookie = useCookie("access_token");
      const refreshTokenCookie = useCookie("refresh_token");
      accessTokenCookie.value = null;
      refreshTokenCookie.value = null;

      await router.push("/auth/login");
    }
  };

  // Refresh access token
  const refreshAccessToken = async () => {
    try {
      const refreshToken = useCookie("refresh_token");
      if (!refreshToken.value) {
        throw new Error("No refresh token available");
      }

      const response = await $fetch<{
        accessToken: string;
        refreshToken: string;
      }>("/api/v1/auth/refresh", {
        baseURL: config.public.apiBaseUrl,
        method: "POST",
        body: {
          refreshToken: refreshToken.value,
        },
      });

      // Update tokens
      const accessTokenCookie = useCookie("access_token");
      const refreshTokenCookie = useCookie("refresh_token");

      accessTokenCookie.value = response.accessToken;
      refreshTokenCookie.value = response.refreshToken;

      authState.accessToken = response.accessToken;
      authState.refreshToken = response.refreshToken;

      return response.accessToken;
    } catch (error) {
      console.error("Token refresh failed:", error);
      await logout();
      throw error;
    }
  };

  // Initiate OIDC flow
  const initiateOIDC = async (
    clientId: string,
    redirectUri: string,
    scope = "openid profile email"
  ) => {
    const state = generateRandomString(32);
    const nonce = generateRandomString(32);

    // Store state and nonce in session storage for validation
    sessionStorage.setItem("oidc_state", state);
    sessionStorage.setItem("oidc_nonce", nonce);

    const params = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      nonce,
    });

    const authUrl = `${
      config.public.oidcIssuer
    }/auth/authorize?${params.toString()}`;
    window.location.href = authUrl;
  };

  // Handle OIDC callback
  const handleOIDCCallback = async (code: string, state: string) => {
    // Validate state
    const storedState = sessionStorage.getItem("oidc_state");
    if (state !== storedState) {
      throw new Error("Invalid state parameter");
    }

    try {
      const response = await $fetch<{
        user: User;
        accessToken: string;
        refreshToken: string;
      }>("/api/v1/auth/oidc/callback", {
        baseURL: config.public.apiBaseUrl,
        method: "POST",
        body: {
          code,
          state,
        },
      });

      // Store tokens and user info
      const accessTokenCookie = useCookie("access_token");
      const refreshTokenCookie = useCookie("refresh_token");

      accessTokenCookie.value = response.accessToken;
      refreshTokenCookie.value = response.refreshToken;

      authState.user = response.user;
      authState.accessToken = response.accessToken;
      authState.refreshToken = response.refreshToken;
      authState.isAuthenticated = true;

      // Clear session storage
      sessionStorage.removeItem("oidc_state");
      sessionStorage.removeItem("oidc_nonce");

      await router.push("/dashboard");
      return response;
    } catch (error) {
      console.error("OIDC callback failed:", error);
      throw error;
    }
  };

  // Check permissions
  const hasPermission = (permission: string): boolean => {
    if (!authState.user) return false;
    return authState.user.roles.some(
      (role) => role === "system_admin" || role.includes(permission)
    );
  };

  // Check if user has any of the specified roles
  const hasRole = (roles: string | string[]): boolean => {
    if (!authState.user) return false;
    const roleArray = Array.isArray(roles) ? roles : [roles];
    return authState.user.roles.some((role) => roleArray.includes(role));
  };

  // Initialize auth state on app start
  onMounted(() => {
    checkAuth();
  });

  return {
    // State
    user: readonly(toRef(authState, "user")),
    isLoading: readonly(toRef(authState, "isLoading")),
    isAuthenticated: readonly(toRef(authState, "isAuthenticated")),

    // Methods
    login,
    register,
    logout,
    checkAuth,
    refreshAccessToken,
    initiateOIDC,
    handleOIDCCallback,
    hasPermission,
    hasRole,
  };
};

// Utility function to generate random string
function generateRandomString(length: number): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
