# AgentHost Framework

### Objective

This is an experimental framework, intending to explore ways to host AI Agents
that can safely be used by multiple users (or personal agents). Core principles:

- Remote-first agents, with caller authentication

- Agents use explicitly delegated credentials, not ambient developer credentials.

- Agent credentials are not exposed directly to the agent, to reduce the chance
  of credential misuse and leakage.

## Framework components

### Agent API (A2A)

The framework uses the Agent-to-Agent protocol (A2A,
[a2a-protocol.org](http://a2a-protocol.org) ), and [ADK
Go](http://google.golang.org/adk) for agent serving.

> [!TIP]
> Some AI models (e.g. Gemini) have a knowledge cutoff that predates the
> A2A specification. To streamline communicating over A2A, I recommend installing
> the [A2A cli tool](https://github.com/a2aproject/a2a-go/tree/main/cmd), and
> instructing your agent to use it. (quick install with `go install
> github.com/a2aproject/a2a-go/v2/cmd/a2a@latest`)

A2A does not include any requirements for authentication, but it is necessary to
address this before you can really use A2A safely.
There are two different types of authentication to address: User
authentication, and delegated authority.

### User Authentication

For authenticating users, we use OpenID Connect (OIDC), which is pretty standard
across the indusry, and allows us to be flexible on which OIDC Provider we want
to use - Google, Github, and many others provide OpenID compatible APIs.

User authentication is pretty common, but to preserve authentication across
mulitple browser requests, we use a Backend-for-frontend (BFF) pattern. BFF uses
a secure  cookie to store a session ID, and an HTTP middleware layer that
replaces the session cookie with the corresponding `Authorization` header.

The authentication of agents (distinct from users) has not yet been addressed,
as it requires some decisions around defining Agent Identity. See the Future
Work section below.

### Delegated Authority

Delegated authority is how we give the agent the ability to act on our behalf.
Currently, this framework supports 3-legged OAuth (3LO).

In the 3LO flow, users are presented with a list of requested permissions that
they can customize (for example, to only allow read access to a resource). From
there, the selected permissions are requested from the Authorization Service
(e.g. Google's OAuth service), and it generates a token. That token is sent back
to our a2a service, and the service exchanges it for an access token that uses
the user's identity.

In this framework, the access tokens are not given to the agents directly, but
are made available to tools through a `DelegatedAuthProvider` that's injected
into the tool's context.

## Future Work

The following areas are planned for future exploration.

- Agent Identity and authentication
- Durable storage of delegated credentials (e.g. Google Cloud Secret Manager)
