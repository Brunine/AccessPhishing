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
  phone_e164?: string;
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

export type CampaignChannel = "email" | "qr";

export interface Campaign {
  id: string;
  tenant_id: string;
  name: string;
  status: CampaignStatus;
  channel: CampaignChannel;
  landing_url?: string;
  template_id?: string;
  sending_profile_id?: string;
  engine_id?: string;
  engagement_id?: string;
  engagement_status?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export type EngagementStatus =
  | "draft"
  | "pending_authorization"
  | "authorized"
  | "active"
  | "expired"
  | "terminated";

export interface Engagement {
  id: string;
  tenant_id: string;
  name: string;
  client_name: string;
  status: EngagementStatus;
  effective_status: EngagementStatus;
  roe_reference?: string;
  authorized_scope: string[];
  authorized_at?: string;
  authorized_by?: string;
  starts_at?: string;
  expires_at?: string;
  notes?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface EngagementInput {
  name: string;
  client_name: string;
  roe_reference?: string | null;
  authorized_scope?: string[];
  starts_at?: string | null;
  expires_at?: string | null;
  notes?: string | null;
}

export type DomainStatus =
  | "candidate"
  | "pending_purchase"
  | "pending_verification"
  | "verified"
  | "authorized"
  | "active"
  | "suspended"
  | "expired"
  | "retired";

export interface Domain {
  id: string;
  tenant_id: string;
  name: string;
  registrar?: string | null;
  status: DomainStatus;
  registered_at?: string | null;
  expires_at?: string | null;
  dns_provider?: string | null;
  nameservers?: string[];
  tls_status?: string | null;
  notes?: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface DomainInput {
  name: string;
  registrar?: string | null;
  status?: "candidate" | "pending_purchase" | "pending_verification";
  registered_at?: string | null;
  expires_at?: string | null;
  dns_provider?: string | null;
  nameservers?: string[];
  notes?: string | null;
}

export interface DomainPatch {
  registrar?: string | null;
  status?: DomainStatus;
  registered_at?: string | null;
  expires_at?: string | null;
  dns_provider?: string | null;
  nameservers?: string[];
  tls_status?: string | null;
  notes?: string | null;
}

export type DomainAssignmentStatus = "pending" | "authorized" | "revoked";

export interface DomainAssignment {
  id: string;
  tenant_id: string;
  domain_id: string;
  engagement_id: string;
  status: DomainAssignmentStatus;
  authorized_by?: string | null;
  authorized_at?: string | null;
  notes?: string | null;
  created_at: string;
  updated_at: string;
}

export interface DomainVerificationChallenge {
  id: string;
  hostname: string;
  token: string;
  txt_record: string;
}

export interface DomainVerificationCheck {
  verified: boolean;
  txt_records?: string[];
  lookup_error?: string;
}

export interface DomainDiagnostics {
  domain: string;
  status: string;
  dns: {
    nameservers?: string[];
    spf?: string;
    dmarc?: string;
    dkim?: string | null;
    dkim_note?: string;
  };
  tls?: {
    subject_cn?: string;
    sans?: string[];
    issuer?: string;
    not_before?: string;
    not_after?: string;
    days_until_expiry?: number;
    covers_domain?: boolean;
  } | null;
  ownership: {
    verified: boolean;
  };
  warnings?: string[];
  errors?: string[];
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

export type DeliveryChannel = "smtp" | "graph" | "gmail" | "sms";

export interface SendingProfile {
  id: string;
  tenant_id: string;
  name: string;
  channel: DeliveryChannel;
  smtp_host: string;
  smtp_port: number;
  smtp_user?: string;
  api_tenant_id?: string;
  api_client_id?: string;
  sms_provider?: string;
  sms_sender_id?: string;
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

export interface QRCodeEntry {
  recipient_id: string;
  contact_id: string;
  token: string;
  click_url: string;
  qr_png_base64: string;
  data_uri: string;
}

export interface QRCodesResponse {
  campaign_id: string;
  channel: CampaignChannel;
  size: number;
  ec_level: string;
  items: QRCodeEntry[];
}

export type TargetState =
  | "pending"
  | "sent"
  | "delivered"
  | "opened"
  | "scanned"
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

export interface ReportTotals {
  recipients: number;
  pending: number;
  sent: number;
  delivered: number;
  opened: number;
  scanned: number;
  clicked: number;
  creds: number;
  session_hijacked: number;
  post_exploitation: number;
  bounced: number;
  failed: number;
}

export interface ReportRates {
  delivered: number;
  opened: number;
  clicked: number;
  creds: number;
  session_hijacked: number;
}

export interface TimelineBucket {
  bucket: string;
  counts: Record<string, number>;
}

export interface CampaignReport {
  campaign_id: string;
  name: string;
  status: string;
  bucket: "hour" | "day";
  totals: ReportTotals;
  rates: ReportRates;
  timeline: TimelineBucket[];
}

export interface CampaignSummary {
  campaign_id: string;
  name: string;
  status: string;
  totals: ReportTotals;
  rates: ReportRates;
}

export interface TenantSummary {
  tenant_id: string;
  totals: ReportTotals;
  rates: ReportRates;
  campaigns: CampaignSummary[];
}

export interface PlatformTenant {
  tenant_id: string;
  name: string;
  slug: string;
  campaigns: number;
  totals: ReportTotals;
  rates: ReportRates;
}

export interface OSINTLookalike {
  domain: string;
  fuzzer: string;
}

export interface OSINTAvailability {
  domain: string;
  available: boolean | null;
  status_code?: number;
}

export interface OSINTCollection {
  domain: string;
  subdomain_source: string;
  subdomains: string[];
  lookalikes: OSINTLookalike[];
  availability: OSINTAvailability[];
}

export interface OSINTResult {
  id: string;
  tenant_id: string;
  domain: string;
  created_by?: string;
  created_at: string;
  result: OSINTCollection;
}

export interface OSINTStatus {
  service: "ok" | "down";
}

export interface User {
  id: string;
  email: string;
  role: "admin" | "operator" | "viewer";
  active: boolean;
  created_at: string;
}

export interface APIKey {
  id: string;
  name: string;
  created_at: string;
  last_used_at?: string;
  revoked_at?: string;
}

export interface CreatedAPIKey {
  id: string;
  name: string;
  created_at: string;
  token: string;
}

export interface ListResponse<T> {
  items: T[];
  limit?: number;
  offset?: number;
}
