// Out-of-band signals to humans. The webhook body is JSON that works with ntfy,
// Slack-compatible incoming webhooks, or a custom receiver; it carries links and
// names only, never values or codes. Push approval (approve from the
// notification itself) plugs in here later.
export type Notification =
  | { type: 'approval_requested'; workspaceId: string; approvalId: string; secretPath: string; clientName: string; reason: string; url: string }
  | { type: 'totp_lockout'; workspaceId: string | null; userEmail: string; until: Date }
  | { type: 'token_reuse'; workspaceId: string; grantId: string; clientName: string; why: 'code_reuse' | 'refresh_reuse' };

export interface Notifier {
  notify(n: Notification): Promise<void>;
}

export function summarize(n: Notification): string {
  switch (n.type) {
    case 'approval_requested':
      return `${n.clientName} wants ${n.secretPath}: "${n.reason}". Approve or deny: ${n.url}`;
    case 'totp_lockout':
      return `Approvals locked for ${n.userEmail} until ${n.until.toISOString()} after repeated wrong authenticator codes.`;
    case 'token_reuse':
      return `A ${n.why === 'code_reuse' ? 'authorization code' : 'refresh token'} for ${n.clientName} was replayed; its access was revoked.`;
  }
}

export class WebhookNotifier implements Notifier {
  constructor(private readonly url: string | undefined) {}

  async notify(n: Notification): Promise<void> {
    const text = summarize(n);
    console.log(JSON.stringify({ level: 'info', msg: 'notification', type: n.type, text }));
    if (!this.url) return;
    try {
      await fetch(this.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text, type: n.type }),
        signal: AbortSignal.timeout(5000),
      });
    } catch (err) {
      console.error(JSON.stringify({ level: 'warn', msg: 'notification webhook failed', error: String(err) }));
    }
  }
}
