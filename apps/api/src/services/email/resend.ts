// Resend email service: welcome, invite, contact

export async function sendWelcomeEmail(env: { RESEND_API_KEY?: string; INVITE_FROM_EMAIL?: string }, to: string, firstName: string, ctaUrl: string, ctaText: string): Promise<void> {
  if (!env.RESEND_API_KEY || !env.INVITE_FROM_EMAIL) return;
  const subject = 'Welcome to Fidbak';
  const html = renderWelcomeHtml(firstName || 'there', ctaUrl, ctaText);
  const text = `Hi ${firstName || 'there'},\n\nThanks for signing up for Fidbak. Get started: ${ctaUrl}\n\nIf you have any questions, just reply to this email.\n\n— Kenny, Founder`;
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.INVITE_FROM_EMAIL, to: [to], subject, html, text }),
  });
  try { if (!resp.ok) { const body = await resp.text().catch(() => ''); console.error('Resend welcome email failed', resp.status, body); } } catch {}
}

export async function sendInviteEmail(env: { RESEND_API_KEY?: string; INVITE_FROM_EMAIL?: string }, to: string, orgName: string, acceptUrl: string, inviterName?: string): Promise<void> {
  if (!env.RESEND_API_KEY || !env.INVITE_FROM_EMAIL) return;
  const inviter = inviterName && inviterName.trim().length ? inviterName.trim() : orgName;
  const subject = `${inviter} invited you to join ${orgName} on Fidbak`;
  const html = renderInviteHtml(inviter, orgName, acceptUrl);
  const text = `You’ve been invited to join ${orgName} on Fidbak.\n\nAccept invite: ${acceptUrl}\n\nIf you didn’t expect this, you can ignore this email.`;
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.INVITE_FROM_EMAIL, to: [to], subject, html, text }),
  });
  try { if (!resp.ok) { const body = await resp.text().catch(() => ''); console.error('Resend invite email failed', resp.status, body); } } catch {}
}

export async function sendContactEmail(env: { RESEND_API_KEY?: string; INVITE_FROM_EMAIL?: string }, payload: { fromEmail: string; fromName?: string; message: string; subject?: string }): Promise<void> {
  if (!env.RESEND_API_KEY || !env.INVITE_FROM_EMAIL) return;
  const to = 'kenny@fidbak.dev';
  const subject = (payload.subject || 'Fidbak: Contact Sales').trim();
  const safeFrom = payload.fromEmail || 'unknown@fidbak.dev';
  const fromName = (payload.fromName || 'Fidbak user').trim();
  const html = `\n    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.5;color:#111">\n      <h2 style=\"margin:0 0 12px\">Contact Sales</h2>\n      <p><strong>From:</strong> ${fromName} &lt;${safeFrom}&gt;</p>\n      <pre style=\"white-space:pre-wrap;background:#f8f9fa;border:1px solid #eee;border-radius:8px;padding:12px;margin-top:12px\">${payload.message}</pre>\n    </div>\n  `;
  const text = `Contact Sales\nFrom: ${fromName} <${safeFrom}>\n\n${payload.message}`;
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.INVITE_FROM_EMAIL, to: [to], subject, html, text, reply_to: safeFrom }),
  });
  try { if (!resp.ok) { const body = await resp.text().catch(() => ''); console.error('Resend contact email failed', resp.status, body); } } catch {}
}

export function renderWelcomeHtml(firstName: string, ctaUrl: string, ctaText: string): string {
  const safe = firstName || 'there';
  // Template copied from fidbak-dash/email-templates/welcome.html
  const tpl = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome to Fidbak</title>
  </head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f9fafb;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f9fafb; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #f97316 0%, #ea580c 100%); padding: 40px 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #ffffff; font-size: 32px; font-weight: 700; letter-spacing: -0.5px;">
                Fidbak
              </h1>
              <p style="margin: 8px 0 0; color: rgba(255,255,255,0.9); font-size: 14px;">
                Lightweight customer feedback platform
              </p>
            </td>
          </tr>

          <!-- Content -->
          <tr>
            <td style="padding: 40px;">
              <p style="margin: 0 0 8px; color: #111827; font-size: 16px; line-height: 1.6;">
                Hi {first_name},
              </p>

              <p style="margin: 0 0 16px; color: #4b5563; font-size: 16px; line-height: 1.6;">
                I’m Kenny. Thanks for signing up for Fidbak.
              </p>

              <p style="margin: 0 0 16px; color: #4b5563; font-size: 16px; line-height: 1.6;">
                I started Fidbak to make feedback simple and useful so you can make better, user driven decisions for your product and business.
              </p>

              <p style="margin: 0 0 24px; color: #4b5563; font-size: 16px; line-height: 1.6;">
                Whether you are just exploring or ready to collect feedback on your site, I am glad you are here.
              </p>

              <!-- Quick Start Box -->
              <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
                <tr>
                  <td style="background-color: #fef3c7; padding: 20px; border-radius: 8px; border-left: 4px solid #f97316;">
                    
                    <p style="margin: 0; color: #78350f; font-size: 14px; line-height: 1.5;">If you have any questions or need help with integrating Fidbak into your site, hit reply and I will get back to you. I read and answer every message myself.</p>
                  </td>
                </tr>
              </table>

              <p style="margin: 0 0 4px; color: #4b5563; font-size: 16px; line-height: 1.6;">
                Glad to have you with us.
              </p>
              <br>

              <p style="margin: 0; color: #111827; font-size: 16px; line-height: 1.6;">
                <strong>Kenny</strong><br>
                <span style="color: #6b7280; font-size: 14px;">Founder, Fidbak</span>
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 24px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb;">
              <p style="margin: 0; color: #9ca3af; font-size: 12px; text-align: center; line-height: 1.5;">
                © 2025 Fidbak. All rights reserved.<br>
                You're receiving this because you created a Fidbak account.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
  return tpl.replace('{first_name}', safe);
}

export function renderInviteHtml(inviterName: string, orgName: string, acceptUrl: string): string {
  const inviter = inviterName || 'A teammate';
  const org = orgName || 'your team';
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>You're invited to Fidbak</title></head><body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background-color:#f9fafb;"><table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f9fafb;padding:40px 20px;"><tr><td align="center"><table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);"><tr><td style="background:linear-gradient(135deg,#f97316 0%,#ea580c 100%);padding:40px 40px 30px;text-align:center;"><h1 style="margin:0;color:#ffffff;font-size:28px;font-weight:700;letter-spacing:-0.3px;">You're invited to Fidbak</h1><p style="margin:8px 0 0;color:rgba(255,255,255,0.9);font-size:14px;">Lightweight customer feedback platform</p></td></tr><tr><td style="padding:40px;"><p style="margin:0 0 16px;color:#111827;font-size:16px;line-height:1.6;">Hey there,</p><p style="margin:0 0 16px;color:#4b5563;font-size:16px;line-height:1.6;"><strong>${inviter}</strong> has invited you to join <strong>${org}</strong> on Fidbak.</p><div style="text-align:center;margin:24px 0;"><a href="${acceptUrl}" style="display:inline-block;background-color:#f97316;color:#ffffff;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:600;">Accept invite</a></div><p style="margin:0;color:#6b7280;font-size:13px;line-height:1.6;">If you didn’t expect this, you can ignore this email.</p></td></tr><tr><td style="padding:24px 40px;background-color:#f9fafb;border-top:1px solid #e5e7eb;"><p style="margin:0;color:#9ca3af;font-size:12px;text-align:center;line-height:1.5;">© 2025 Fidbak. All rights reserved.</p></td></tr></table></td></tr></table></body></html>`;
}
