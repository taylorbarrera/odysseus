# Outlook / Office 365 email accounts

Odysseus supports Outlook / Microsoft 365 email accounts two ways:

1. **OAuth2 (recommended, required for most accounts)** — click
   "Connect with Microsoft" when adding or editing an account with the
   Outlook / Office 365 preset. This is required for almost every modern
   Outlook.com, Hotmail, and Microsoft 365 mailbox.
2. **Username/password** — still works for the shrinking set of tenants that
   have not yet disabled basic authentication for IMAP/SMTP (mostly legacy
   on-prem-adjacent or explicitly reconfigured tenants).

## Why OAuth is required

Microsoft disables basic authentication for Outlook and Microsoft 365 in most
modern accounts and tenants. If you try to add an Outlook account with a
normal password, Microsoft may return errors such as:

- `IMAP: AUTHENTICATE failed`
- `SMTP: 535 5.7.139 Authentication unsuccessful, basic authentication is disabled`

This is expected — use OAuth instead of the password form for these accounts.

## How Odysseus's Microsoft OAuth works

Odysseus authenticates to Exchange Online over **IMAP and SMTP with XOAUTH2**
rather than the Graph mail REST API. Microsoft has not deprecated IMAP/SMTP
themselves — only *basic* (password) authentication is being retired — so
OAuth2 on IMAP/SMTP remains fully supported and lets Odysseus reuse its
existing IMAP/SMTP pipeline (message parsing, threading, attachments, etc.)
instead of standing up a parallel Graph API client.

## Setup (self-hosted)

1. Register an app in [Microsoft Entra ID](https://entra.microsoft.com) (Azure
   Portal → App registrations → New registration). Choose "Accounts in any
   organizational directory and personal Microsoft accounts" unless you only
   ever need a single tenant.
2. Under **Authentication**, add a Web platform redirect URI:
   `http://localhost:7000/api/email/oauth/microsoft/callback` (adjust host and
   port for hosted/HTTPS installs, and set `MICROSOFT_OAUTH_REDIRECT_URI` to
   match exactly).
3. Under **Certificates & secrets**, create a client secret.
4. Under **API permissions**, add the delegated Office 365 Exchange Online
   permissions `IMAP.AccessAsUser.All` and `SMTP.Send`, plus `offline_access`.
5. Set `MICROSOFT_OAUTH_CLIENT_ID` and `MICROSOFT_OAUTH_CLIENT_SECRET` in your
   `.env` (see `.env.example` for the full walkthrough, including the optional
   `MICROSOFT_OAUTH_TENANT` and `MICROSOFT_OAUTH_REDIRECT_URI` overrides).
   Alternatively, skip editing `.env` entirely: add an email account with the
   "Outlook / Office 365" preset and click "Connect" — if the app isn't
   configured yet, an admin will see inline Client ID/Secret/Tenant fields
   right there (the secret is encrypted at rest, the same way OAuth account
   tokens are, and a value entered there takes priority over the env vars).
   Non-admins see a message asking them to have an admin configure it.
6. Restart Odysseus, then add an email account with the "Outlook / Office 365"
   preset and click "Connect with Microsoft".

The mailbox that grants consent must match the account's IMAP/SMTP username —
Odysseus verifies this via Microsoft Graph's `/me` endpoint before saving the
token, the same identity check used for Google OAuth accounts.
