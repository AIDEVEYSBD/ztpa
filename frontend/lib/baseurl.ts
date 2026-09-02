/**
 * The canonical origin used to build absolute links in emails (magic-link,
 * password reset, invite).
 *
 * THIS FUNCTION DELIBERATELY DOES NOT LOOK AT THE REQUEST.
 *
 * It used to: it read `x-forwarded-host` / `host` and built the link from
 * whatever the client asked for. `Host` is client-controlled — it is a request
 * header like any other, and nothing between a browser and this app is required
 * to rewrite it — so `curl -H 'Host: attacker.example' .../forgot -d
 * email=admin@...` produced a real, valid, single-use sign-in token embedded in
 * a link pointing at the attacker's server. The victim clicks the link in a mail
 * that genuinely came from us, the token is handed to the attacker, and the
 * attacker replays it here. That is account takeover with one header, and the
 * accounts worth taking are exactly the ones that can be reset by email.
 *
 * A reverse proxy that overwrites `Host`/`x-forwarded-host` prevents it, but the
 * safety of a security-critical link must not depend on a deployment detail that
 * is invisible from this file — and `render.yaml` ships the backend publicly
 * reachable, so "there is always a trusted proxy in front" is not an assumption
 * this repo has earned. The origin is therefore pinned to configuration:
 * `APP_URL`, then `AUTH_URL`, then the localhost default that lets a fresh clone
 * work. All three are values an operator set; none can be moved by a request.
 *
 * The trade-off is stated plainly: on a deploy that never sets APP_URL, links
 * point at localhost and are useless. That is a visible, self-reporting
 * misconfiguration. The previous behaviour was an invisible one that minted
 * credentials for whoever asked, so this is the direction to fail in — and the
 * warning below names the fix the first time a link is built without it.
 */

/** Trim trailing slashes so `${getBaseUrl()}/reset` never doubles them. */
function clean(v: string | undefined): string {
  return (v ?? "").trim().replace(/\/+$/, "");
}

/** Warn once per process, not once per email — a reset storm must not become a
 *  log flood, but the operator has to be told at least once. */
let warned = false;

export function getBaseUrl(): string {
  const pinned = clean(process.env.APP_URL) || clean(process.env.AUTH_URL);
  if (pinned) return pinned;

  if (!warned) {
    warned = true;
    console.warn(
      "[baseurl] APP_URL (or AUTH_URL) is not set, so sign-in/reset/invite links " +
      "are being built against http://localhost:3000. Set APP_URL to this " +
      "deployment's canonical origin. The request's Host header is deliberately " +
      "NOT used: it is client-controlled, and a link built from it hands a live " +
      "single-use token to whoever set it.",
    );
  }
  return "http://localhost:3000";
}
