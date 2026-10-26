// Qorvex TypeScript API Client
// Provides typed API calls with JWT authentication from localStorage

const API_BASE = "/api/v1";

// ============================================================================
// Authentication types
// ============================================================================

export interface LoginCredentials {
    username: string;
    password: string;
}

export interface LoginResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    user: UserInfo;
}

export interface UserInfo {
    id: string;
    username: string;
    email: string;
    role: string;
    permissions: string[];
}

export interface AuthState {
    isAuthenticated: boolean;
    user: UserInfo | null;
    token: string | null;
    expiresAt: number | null;
    loading: boolean;
    error: string | null;
}

// ============================================================================
// Auth storage helpers
// ============================================================================

const TOKEN_KEY = "qorvex_token";
const REFRESH_KEY = "qorvex_refresh_token";
const USER_KEY = "qorvex_user";

function getStoredToken(): string | null {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(TOKEN_KEY);
}

function getStoredRefreshToken(): string | null {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(REFRESH_KEY);
}

function getStoredUser(): UserInfo | null {
    if (typeof window === "undefined") return null;
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
}

function setTokens(token: string, refresh: string, user: UserInfo): void {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(REFRESH_KEY, refresh);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
}

function clearTokens(): void {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
}

// ============================================================================
// Auth state management
// ============================================================================

let authState: AuthState = {
    isAuthenticated: false,
    user: null,
    token: getStoredToken(),
    expiresAt: null,
    loading: false,
    error: null,
};

export function getAuthState(): AuthState {
    return authState;
}

export function login(credentials: LoginCredentials): Promise<LoginResponse> {
    authState = {
        ...authState,
        loading: true,
        error: null,
    };

    return fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(credentials),
    })
        .then(async (res) => {
            if (!res.ok) {
                const err = await res.json();
                authState = {
                    ...authState,
                    loading: false,
                    error: err.detail || res.statusText,
                };
                throw new Error(authState.error);
            }
            return res.json();
        })
        .then((data: LoginResponse) => {
            setTokens(data.access_token, data.refresh_token, data.user);
            authState = {
                isAuthenticated: true,
                user: data.user,
                token: data.access_token,
                expiresAt: Date.now() + data.expires_in * 1000,
                loading: false,
                error: null,
            };
            return data;
        })
        .catch((err) => {
            authState = {
                ...authState,
                loading: false,
                error: err.message || "Login failed",
            };
            throw err;
        });
}

export function logout(): Promise<void> {
    // Call server logout if we have a token
    const token = getStoredToken();
    if (token) {
        fetch(`${API_BASE}/auth/logout`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
            },
        }).catch(() => {}); // Don't fail on logout
    }

    clearTokens();
    authState = {
        isAuthenticated: false,
        user: null,
        token: null,
        expiresAt: null,
        loading: false,
        error: null,
    };

    return Promise.resolve();
}

export function refreshToken(): Promise<LoginResponse> {
    const refresh = getStoredRefreshToken();
    if (!refresh) {
        return Promise.reject(new Error("No refresh token available"));
    }

    return fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ refresh_token: refresh }),
    })
        .then(async (res) => {
            if (!res.ok) {
                const err = await res.json();
                logout(); // Clear stale tokens
                throw new Error(err.detail || res.statusText);
            }
            return res.json();
        })
        .then((data: LoginResponse) => {
            setTokens(data.access_token, data.refresh_token, data.user);
            authState = {
                isAuthenticated: true,
                user: data.user,
                token: data.access_token,
                expiresAt: Date.now() + data.expires_in * 1000,
                loading: false,
                error: null,
            };
            return data;
        })
        .catch((err) => {
            authState = {
                ...authState,
                isAuthenticated: false,
                user: null,
                token: null,
                expiresAt: null,
                loading: false,
                error: err.message,
            };
            logout();
            throw err;
        });
}

// Get current user info
export function getCurrentUser(): UserInfo | null {
    return authState.user;
}

// Check if user is authenticated
export function isAuthenticated(): boolean {
    // If we have a token in state, check expiry
    if (authState.token && authState.expiresAt) {
        if (Date.now() > authState.expiresAt) {
            // Token expired, try refresh
            return refreshToken().then(() => true).catch(() => false);
        }
        return true;
    }

    // Check localStorage as fallback
    const token = getStoredToken();
    if (token) {
        // Could also decode JWT to check expiry
        authState = {
            ...authState,
            token,
            isAuthenticated: true,
            user: getStoredUser(),
            expiresAt: /* compute from JWT */ 0,
        };
        return true;
    }

    authState = {
        ...authState,
        isAuthenticated: false,
        user: null,
        token: null,
        expiresAt: null,
    };
    return false;
}

// ============================================================================
// API request function with automatic auth
// ============================================================================

function getAuthHeaders(): HeadersInit {
    const token = authState.token || getStoredToken();

    if (!token) {
        return {
            "Content-Type": "application/json",
        };
    }

    return {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
    };
}

async function request<T>(
    endpoint: string,
    options?: RequestInit,
): Promise<T> {
    // Ensure we're authenticated
    if (!isAuthenticated()) {
        throw new Error("Not authenticated");
    }

    const res = await fetch(`${API_BASE}${endpoint}`, {
        headers: getAuthHeaders(),
        ...options,
    });

    if (!res.ok) {
        // 401 - token might be expired, try refresh
        if (res.status === 401) {
            try {
                await refreshToken();
                // Retry with new token
                return request(endpoint, options);
            } catch (refreshErr) {
                // Refresh failed, user needs to login again
                logout();
                throw new Error("Session expired, please login again");
            }
        }

        const error = await res.json().catch(() => ({ error: res.statusText }));
        throw new Error(error.error || res.statusText);
    }

    return res.json();
}

// Convenience functions
export async function get<T>(endpoint: string): Promise<T> {
    return request<T>(endpoint);
}

export async function post<T, D>(endpoint: string, data: D): Promise<T> {
    return request<T>(endpoint, {
        method: "POST",
        body: JSON.stringify(data),
    });
}

export async function put<T, D>(endpoint: string, data: D): Promise<T> {
    return request<T>(endpoint, {
        method: "PUT",
        body: JSON.stringify(data),
    });
}

export async function del<T>(endpoint: string): Promise<T> {
    return request<T>(endpoint, { method: "DELETE" });
}

// Export types for use in components
export { type LoginCredentials, type LoginResponse, type UserInfo, type AuthState, type LoginOptions };