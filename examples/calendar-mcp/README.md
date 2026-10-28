# Authenticated Google Calendar MCP Server

This example demonstrates how to build an authenticated [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that reads a user's Google Calendar by reusing the **Login (OIDC)** and **Delegated Credentials (OAuth 3LO)** components from the **AgentHost** framework.

---

## 🌟 Key Architecture & Principles

1. **User Authentication (BFF + OIDC)**:
   - Users authenticate using standard Google OpenID Connect at `/login`.
   - The server establishes a secure session cookie (`session_id`) and maintains the OIDC ID token in the session store.
2. **Explicit Delegated Authority (3LO OAuth2)**:
   - The server requests explicit, user-customizable OAuth scopes (e.g. `https://www.googleapis.com/auth/calendar.readonly`) at `/authorize/google`.
   - Delegated access tokens and refresh tokens are securely stored in a `CredentialStore` (Google Secret Manager or In-Memory) scoped to the user's email.
3. **No Ambient Credentials**:
   - The MCP tools never use ambient developer or service credentials.
   - Every tool call executes under the authenticated user's delegated credentials via `auth.DelegatedAuthProvider` and `auth.NewClient("google")`.
4. **Multi-Transport MCP Support**:
   - **Streamable HTTP** transport at `/mcp` (recommended for modern MCP clients).
   - **Server-Sent Events (SSE)** transport at `/sse`.

---

## 🛠️ Available MCP Tools

| Tool Name | Description | Arguments |
| :--- | :--- | :--- |
| `read_calendar` | Retrieves meetings, events, attendee statuses, and video conference links from the primary or specified calendar. | `date` *(optional string, `YYYY-MM-DD`, defaults to today)*<br>`calendar_id` *(optional string, defaults to `primary`)* |
| `get_user_info` | Returns the currently authenticated user identity and list of authorized delegated providers. | None |

---

## 🚀 Quick Start

### 1. Configure OAuth Credentials

Create a `config.yaml` file in the project root or configure via environment variables:

```yaml
oauth:
  google:
    client_id: "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com"
    client_secret: "YOUR_GOOGLE_CLIENT_SECRET"
```

> [!TIP]
> Ensure your Google Cloud OAuth 2.0 Client has the following redirect URIs configured:
> - `http://localhost:9002/login`
> - `http://localhost:9002/authorize/google`

### 2. Run the MCP Server

```bash
go run ./examples/calendar-mcp -port 9002
```

Console output will display:
```
=================================================================
🚀 Google Calendar MCP Server running on http://localhost:9002
👉 Login URL:                     http://localhost:9002/login
👉 Status Dashboard:              http://localhost:9002/status
👉 Authorize Google Calendar:     http://localhost:9002/authorize/google
👉 MCP Streamable HTTP Endpoint:  http://localhost:9002/mcp
👉 MCP SSE Endpoint:              http://localhost:9002/sse
👉 Health Check:                  http://localhost:9002/health
=================================================================
```

### 3. Log In and Authorize Calendar Access

1. Open your browser and navigate to:
   ```
   http://localhost:9002/login
   ```
2. Sign in with your Google account.
3. Visit the authorization page to grant Google Calendar read permissions:
   ```
   http://localhost:9002/authorize/google
   ```
4. View your active session and enabled providers on the dashboard:
   ```
   http://localhost:9002/status
   ```
   Copy your `Session ID` from this page for configuring your MCP client.

---

## 🔌 Connecting MCP Clients

### Claude Desktop Configuration

Add the server to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "google-calendar": {
      "url": "http://localhost:9002/mcp",
      "headers": {
        "Authorization": "Bearer <YOUR_SESSION_ID>"
      }
    }
  }
}
```

### Cursor / Gemini / Custom MCP Client

Configure the MCP remote endpoint:
- **Transport**: `Streamable HTTP` (or `SSE`)
- **URL**: `http://localhost:9002/mcp` (or `http://localhost:9002/sse`)
- **Headers**:
  - `Authorization: Bearer <YOUR_SESSION_ID>` (or `Authorization: Bearer <OAUTH_ACCESS_TOKEN>`)

---

## 🧪 Running Tests

To run the full suite of unit and integration tests (including mock Google Calendar API tests and unauthenticated error verification):

```bash
go test -v ./examples/calendar-mcp/...
```
