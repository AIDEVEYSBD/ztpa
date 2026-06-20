import { Resend } from "resend";

const FROM = process.env.EMAIL_FROM || "ZeroTrust Advisor <onboarding@resend.dev>";
const KEY = process.env.RESEND_API_KEY;

function template(heading: string, body: string, cta: string, url: string): string {
  return `<!doctype html><html><body style="margin:0;background:#1A1A24;font-family:Inter,Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#1A1A24;padding:32px 0">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0" style="background:#2E2E38;border-radius:16px;overflow:hidden">
        <tr><td style="height:6px;background:#FFE600"></td></tr>
        <tr><td style="padding:28px 32px;color:#F6F6FA">
          <div style="font-weight:800;font-size:18px;color:#FFE600;letter-spacing:-0.5px">EY · ZeroTrust Policy Advisor</div>
          <h1 style="font-size:20px;margin:18px 0 8px">${heading}</h1>
          <p style="color:#C4C4CD;font-size:14px;line-height:1.6;margin:0 0 22px">${body}</p>
          <a href="${url}" style="display:inline-block;background:#FFE600;color:#1A1A24;font-weight:700;text-decoration:none;padding:11px 20px;border-radius:8px;font-size:14px">${cta}</a>
          <p style="color:#747480;font-size:12px;margin:22px 0 0">Or paste this link:<br><span style="color:#C4C4CD;word-break:break-all">${url}</span></p>
        </td></tr>
      </table>
    </td></tr>
  </table></body></html>`;
}

async function send(to: string, subject: string, html: string, devLink: string) {
  if (!KEY) {
    console.log(`\n[email disabled — no RESEND_API_KEY]\n  to: ${to}\n  ${subject}\n  link: ${devLink}\n`);
    return { sent: false, devLink };
  }
  try {
    await new Resend(KEY).emails.send({ from: FROM, to, subject, html });
    return { sent: true };
  } catch (e) {
    console.log(`[email error] ${e} — link: ${devLink}`);
    return { sent: false, devLink, error: String(e) };
  }
}

export const emails = {
  magic: (to: string, url: string) =>
    send(to, "Your sign-in link", template("Sign in", "Click below to sign in. This link expires in 30 minutes and works once.", "Sign in", url), url),
  reset: (to: string, url: string) =>
    send(to, "Reset your password", template("Reset your password", "Click below to set a new password. This link expires in 30 minutes.", "Reset password", url), url),
  invite: (to: string, url: string, role: string) =>
    send(to, "You're invited to ZeroTrust Policy Advisor",
      template("You've been invited", `You've been added as <b style="color:#FFE600">${role}</b>. Click below to activate your account and set a password.`, "Activate account", url), url),
};
