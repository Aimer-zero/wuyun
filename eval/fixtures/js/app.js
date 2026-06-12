// Static-only fixture for Wuyun helper regression. Never execute this file.
const socketPath = "/socket/chat";
const apiPath = "/api/admin/roles";
const graphQuery = `query Viewer($id: ID!) { viewer(id: $id) { id } }`;

async function updateRole(userId, role, csrfToken) {
  const timestamp = String(Date.now());
  const nonce = "eval-nonce";
  const signature = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${timestamp}:${nonce}:${role}`),
  );
  const tokenValue = localStorage.getItem("accessToken");
  return fetch(apiPath, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokenValue}`,
      "X-CSRF": csrfToken,
      "X-Signature": String(signature),
    },
    body: JSON.stringify({ userId, role }),
  });
}

const channel = new WebSocket(`wss://app.example.invalid${socketPath}`);
channel.addEventListener("message", event => console.debug("socket", event.data));
