# Abblix.SecurityEvents.MinimalApi

ASP.NET Core Minimal API integration for `Abblix.SecurityEvents`. It maps the two endpoints that
receive a token and nothing more: `MapBackChannelLogoutEndpoint` for OpenID Connect Back-Channel
Logout 1.0, and `MapPushDeliveryEndpoint` for RFC 8935 push delivery. The request and response rules
live in the core, so this package is the transport and the route pattern.

## Which adapter maps which endpoint

There are two Minimal API packages in this family, and the line between them is not the one that
first suggests itself. It is **not** receiver here and transmitter there: the Shared Signals package
holds receiver-role code of its own - the stream management client, the transmitter discovery
client. The question that decides placement is whether the endpoint stops making sense **without a
stream**:

- **Back-Channel Logout** - one token, delivered once, from a provider the relying party already
  knows through OpenID Connect. Nothing was negotiated, nothing was subscribed to. Here.
- **Push delivery** - "accept a SET at this address" (RFC 8935 Section 2.1). The URL is the
  receiver's own and carries no stream identity; a receiver can be handed events by a counterparty
  known from anywhere. Here.
- **Stream management, status, subjects, verification, the `ssf-configuration` document and the
  transmitter's poll endpoint** - each is meaningless without a stream, and the poll address is
  addressed *by stream identifier*. Those live in
  [Abblix.SharedSignals.MinimalApi](https://www.nuget.org/packages/Abblix.SharedSignals.MinimalApi).

Push and poll are the pair worth understanding, because both are core delivery specifications
(RFC 8935 and RFC 8936) and yet they land in different packages. What separates them is not which
document defines the protocol but whether a stream is part of the addressing: the push intake just
accepts a token, while the transmitter's poll endpoint serves one stream's queue and its URL is
built per stream. The specification says how to carry an event; the stream says to whom - and that
second half is Shared Signals.

The practical consequence is why the split is kept: a relying party that wants only Back-Channel
Logout takes this package and nothing else. Folding the two together would put the whole Shared
Signals public surface in front of every such host, none of which will ever call it.

## Use

```csharp
builder.Services.AddSecurityEvents();
builder.Services.AddJwksKeyResolution(options =>
    options.JwksUris["https://op.example.com"] = new Uri("https://op.example.com/.well-known/jwks"));
builder.Services.AddBackChannelLogoutReceiver(new BackChannelLogoutValidationOptions
{
    ExpectedIssuers = ["https://op.example.com"],
    ExpectedAudience = "this-client-id",
});

// Ends the sessions a validated notification names - the half only the application can write.
builder.Services.AddSingleton<ILogoutNotificationSink, MySessionStore>();

app.MapBackChannelLogoutEndpoint("/backchannel-logout");
```

The route is whatever the client registered with its provider as `backchannel_logout_uri`.

## What the host still owns

- **Where the sessions are.** Section 2.7 makes locating and clearing them the relying party's,
  because only it knows where it keeps them. That is the sink above.
- **Which keys to trust.** Key resolution is deployment knowledge, so the core asks for it rather
  than guessing.
- **Resilience and timeouts** of anything fetched outward, through `IHttpClientFactory` as usual.

## Part of the Abblix product family

Abblix.SecurityEvents.MinimalAPI is the ASP.NET Core adapter of [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents), which owns the token and the wire. Event streams and their management layer live in [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals), and the identity provider that emits these events is [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

## License

Abblix.SecurityEvents.MinimalAPI is licensed under the [Apache License 2.0](https://github.com/Abblix/Oidc.Server/blob/master/LICENSES/Apache-2.0.txt).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
