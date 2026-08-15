# Abblix.SecurityEvents.MinimalApi

ASP.NET Core Minimal API integration for `Abblix.SecurityEvents`. It maps the receiving side of
OpenID Connect Back-Channel Logout 1.0 onto a route, and contains nothing else: the request and the
response rules live in the core, so this package is the transport and the route pattern.

## Use

```csharp
builder.Services.AddSecurityEvents();
builder.Services.AddJwksKeyResolution(options => { /* where the provider's keys live */ });
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

## Licence

See [LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).
