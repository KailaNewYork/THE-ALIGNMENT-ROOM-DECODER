// Cloudflare Pages Functions: password gate for the whole Alignment Room app.
// Configure ALIGNMENT_ROOM_PASSWORD as an encrypted secret in Cloudflare Pages.
// Never put the password in this file or in index.html.
export async function onRequest(context) {
  const password = context.env.ALIGNMENT_ROOM_PASSWORD;
  if (!password) {
    return new Response('Client access is not configured yet.', {
      status: 503,
      headers: { 'Cache-Control': 'no-store', 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }

  const authorization = context.request.headers.get('Authorization') || '';
  let valid = false;
  if (authorization.startsWith('Basic ')) {
    try {
      const decoded = atob(authorization.slice(6).trim());
      const colon = decoded.indexOf(':');
      if (colon !== -1) {
        const username = decoded.slice(0, colon);
        const enteredPassword = decoded.slice(colon + 1);
        // Shared account name; the password is the only secret.
        valid = username === 'client' && enteredPassword === password;
      }
    } catch (_) {
      valid = false;
    }
  }

  if (!valid) {
    return new Response('The Alignment Room App — Client Access Required', {
      status: 401,
      headers: {
        'WWW-Authenticate': 'Basic realm="The Alignment Room App — Client Access", charset="UTF-8"',
        'Cache-Control': 'no-store',
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Robots-Tag': 'noindex, nofollow'
      }
    });
  }

  const response = await context.next();
  const headers = new Headers(response.headers);
  headers.set('Cache-Control', 'private, no-store');
  headers.set('X-Robots-Tag', 'noindex, nofollow');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
