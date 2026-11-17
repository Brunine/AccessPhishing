import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  ApiError,
  clearSession,
  detectRole,
  getKey,
  getStoredRole,
  setKey as persistKey,
  setStoredRole,
} from "./api/client";
import type { Role } from "./api/types";

interface Session {
  key: string;
  role: Role | null;
  ready: boolean;
  signIn: (key: string) => Promise<void>;
  signOut: () => void;
  isAdmin: boolean;
  isOperator: boolean; // operator OR admin
}

const SessionCtx = createContext<Session | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [key, setKeyState] = useState<string>(getKey());
  const [role, setRole] = useState<Role | null>(
    (getStoredRole() as Role) || null
  );
  const [ready, setReady] = useState(false);

  // On mount, if a key is present but role unknown, re-probe it.
  useEffect(() => {
    let cancelled = false;
    async function boot() {
      if (!key) {
        setReady(true);
        return;
      }
      if (role) {
        setReady(true);
        return;
      }
      try {
        const r = await detectRole();
        if (!cancelled) {
          setRole(r);
          setStoredRole(r);
        }
      } catch {
        if (!cancelled) {
          clearSession();
          setKeyState("");
          setRole(null);
        }
      } finally {
        if (!cancelled) setReady(true);
      }
    }
    void boot();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const signIn = useCallback(async (newKey: string) => {
    persistKey(newKey);
    setKeyState(newKey);
    try {
      const r = await detectRole();
      setRole(r);
      setStoredRole(r);
    } catch (e) {
      clearSession();
      setKeyState("");
      setRole(null);
      if (e instanceof ApiError && e.status === 401) {
        throw new Error("Invalid API key (401).");
      }
      throw e;
    }
  }, []);

  const signOut = useCallback(() => {
    clearSession();
    setKeyState("");
    setRole(null);
  }, []);

  const value = useMemo<Session>(
    () => ({
      key,
      role,
      ready,
      signIn,
      signOut,
      isAdmin: role === "admin",
      isOperator: role === "admin" || role === "operator",
    }),
    [key, role, ready, signIn, signOut]
  );

  return <SessionCtx.Provider value={value}>{children}</SessionCtx.Provider>;
}

export function useSession(): Session {
  const ctx = useContext(SessionCtx);
  if (!ctx) throw new Error("useSession must be used within SessionProvider");
  return ctx;
}
