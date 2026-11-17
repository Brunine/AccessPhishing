// Thin fetch wrapper around the PhishForge API. Every request carries the
// operator's X-API-Key (stored in localStorage). Errors are RFC 7807
// problem+json; we surface title + detail as an ApiError.

import type {
  Activity,
  Approval,
  Campaign,
  CampaignLink,
  CampaignTarget,
  Contact,
  Group,
  ImportResult,
  ListResponse,
  SendingProfile,
  Template,
  Tenant,
} from "./types";

const KEY_STORAGE = "phishforge.apiKey";
const ROLE_STORAGE = "phishforge.role";

export function getKey(): string {
  try {
    return localStorage.getItem(KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

export function setKey(key: string): void {
  try {
    localStorage.setItem(KEY_STORAGE, key);
  } catch {
    /* ignore (private mode) */
  }
}

export function clearSession(): void {
  try {
    localStorage.removeItem(KEY_STORAGE);
    localStorage.removeItem(ROLE_STORAGE);
  } catch {
    /* ignore */
  }
}

export function getStoredRole(): string {
  try {
    return localStorage.getItem(ROLE_STORAGE) ?? "";
  } catch {
    return "";
  }
}

export function setStoredRole(role: string): void {
  try {
    localStorage.setItem(ROLE_STORAGE, role);
  } catch {
    /* ignore */
  }
}

export class ApiError extends Error {
  status: number;
  title: string;
  detail: string;
  constructor(status: number, title: string, detail: string) {
    super(detail || title || `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.title = title;
    this.detail = detail;
  }
}

const BASE = "/api/v1";

async function request<T>(
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  const headers: Record<string, string> = { "X-API-Key": getKey() };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 204) return undefined as T;

  const text = await res.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!res.ok) {
    const p = (data ?? {}) as { title?: string; detail?: string };
    throw new ApiError(
      res.status,
      p.title ?? res.statusText,
      p.detail ?? (typeof data === "string" ? data : "")
    );
  }
  return data as T;
}

function items<T>(r: ListResponse<T>): T[] {
  return r.items ?? [];
}

// Probe the principal's role without a dedicated whoami endpoint: admin can
// list tenants; operator can list campaigns; otherwise viewer. A 401 means the
// key itself is invalid.
export async function detectRole(): Promise<"admin" | "operator" | "viewer"> {
  try {
    await request("GET", "/tenants?limit=1");
    return "admin";
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) throw e;
  }
  try {
    await request("GET", "/campaigns?limit=1");
    return "operator";
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) throw e;
  }
  return "viewer";
}

export const api = {
  health: () => request<{ status: string; db: string }>("GET", "/health"),

  tenants: {
    list: () => request<ListResponse<Tenant>>("GET", "/tenants").then(items),
    create: (b: { name: string; slug: string }) =>
      request<Tenant>("POST", "/tenants", b),
  },

  groups: {
    list: () =>
      request<ListResponse<Group>>("GET", "/contact-groups").then(items),
    create: (b: { name: string }) =>
      request<Group>("POST", "/contact-groups", b),
    remove: (id: string) => request<void>("DELETE", `/contact-groups/${id}`),
  },

  contacts: {
    list: (groupId?: string) =>
      request<ListResponse<Contact>>(
        "GET",
        "/contacts" + (groupId ? `?group_id=${groupId}` : "")
      ).then(items),
    create: (b: Partial<Contact>) => request<Contact>("POST", "/contacts", b),
    remove: (id: string) => request<void>("DELETE", `/contacts/${id}`),
    import: (contacts: Partial<Contact>[], groupId?: string) =>
      request<ImportResult>("POST", "/contacts/import", {
        contacts,
        group_id: groupId || undefined,
      }),
  },

  campaigns: {
    list: () =>
      request<ListResponse<Campaign>>("GET", "/campaigns").then(items),
    get: (id: string) => request<Campaign>("GET", `/campaigns/${id}`),
    create: (b: { name: string }) => request<Campaign>("POST", "/campaigns", b),
    launch: (
      id: string,
      b: {
        group_id?: string;
        contact_ids?: string[];
        template_id?: string;
        sending_profile_id?: string;
        landing_url?: string;
      }
    ) => request<{ status: string; recipients: number }>(
      "POST",
      `/campaigns/${id}/launch`,
      b
    ),
    links: (id: string) =>
      request<ListResponse<CampaignLink>>(
        "GET",
        `/campaigns/${id}/links`
      ).then(items),
    targets: (id: string) =>
      request<ListResponse<CampaignTarget>>(
        "GET",
        `/campaigns/${id}/targets`
      ).then(items),
    send: (id: string) =>
      request<{ status: string }>("POST", `/campaigns/${id}/send`),
  },

  templates: {
    list: () =>
      request<ListResponse<Template>>("GET", "/templates").then(items),
    get: (id: string) => request<Template>("GET", `/templates/${id}`),
    create: (b: Partial<Template>) => request<Template>("POST", "/templates", b),
    update: (id: string, b: Partial<Template>) =>
      request<Template>("PATCH", `/templates/${id}`, b),
    remove: (id: string) => request<void>("DELETE", `/templates/${id}`),
  },

  profiles: {
    list: () =>
      request<ListResponse<SendingProfile>>(
        "GET",
        "/sending-profiles"
      ).then(items),
    create: (b: Record<string, unknown>) =>
      request<SendingProfile>("POST", "/sending-profiles", b),
    remove: (id: string) => request<void>("DELETE", `/sending-profiles/${id}`),
  },

  approvals: {
    list: () =>
      request<ListResponse<Approval>>("GET", "/approvals").then(items),
    request: (b: { subject_type: string; subject_id: string }) =>
      request<Approval>("POST", "/approvals", b),
    approve: (id: string) =>
      request<Approval>("POST", `/approvals/${id}/approve`),
    reject: (id: string) => request<Approval>("POST", `/approvals/${id}/reject`),
  },

  activity: (limit = 50) =>
    request<Activity>("GET", `/activity?limit=${limit}`),
};
