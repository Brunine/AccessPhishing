// Types mirror the Go JSON shapes served by the PhishForge API.

export type Role = "admin" | "operator" | "viewer";

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface Group {
  id: string;
  tenant_id: string;
  name: string;
  created_at: string;
}

export interface Contact {
  id: string;
  tenant_id: string;
  group_id?: string;
  email: string;
  first_name?: string;
  last_name?: string;
  phone?: string;
  attributes?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface ImportResult {
  created: number;
  duplicates: number;
  suppressed: number;
}

export type CampaignStatus =
  | "draft"
  | "scheduled"
  | "running"
  | "paused"
  | "completed"
  | "archived";

export interface Campaign {
  id: string;
  tenant_id: string;
  name: string;
  status: CampaignStatus;
  landing_url?: string;
  template_id?: string;
  sending_profile_id?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface Template {
  id: string;
  tenant_id: string;
  kind: string;
  name: string;
  subject?: string;
  body: string;
  created_at: string;
  updated_at: string;
}

export type TLSMode = "none" | "starttls" | "smtps";

export interface SendingProfile {
  id: string;
  tenant_id: string;
  name: string;
  smtp_host: string;
  smtp_port: number;
  smtp_user?: string;
  from_address: string;
  from_name?: string;
  tls_mode: TLSMode;
  created_at: string;
  updated_at: string;
}

export type ApprovalStatus = "draft" | "approved" | "rejected" | "sent";

export interface Approval {
  id: string;
  tenant_id: string;
  subject_type: string;
  subject_id: string;
  status: ApprovalStatus;
  requested_by?: string;
  decided_by?: string;
  decided_at?: string;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface CampaignLink {
  recipient_id: string;
  contact_id: string;
  token: string;
  click_url: string;
  pixel_url: string;
}

export type TargetState =
  | "pending"
  | "sent"
  | "delivered"
  | "opened"
  | "clicked"
  | "creds"
  | "session_hijacked"
  | "post_exploitation"
  | "bounced"
  | "failed";

export interface CampaignTarget {
  contact_id: string;
  email: string;
  first_name?: string;
  token: string;
  state: TargetState;
  last_event_at?: string;
}

export interface AuditRecord {
  id: string;
  actor_email?: string;
  action: string;
  target_type?: string;
  target_id?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface EventRecord {
  id: string;
  tenant_id: string;
  campaign_id: string;
  contact_id?: string;
  type: string;
  occurred_at: string;
  created_at: string;
}

export interface Activity {
  audit: AuditRecord[];
  events: EventRecord[];
}

export interface ListResponse<T> {
  items: T[];
  limit?: number;
  offset?: number;
}
