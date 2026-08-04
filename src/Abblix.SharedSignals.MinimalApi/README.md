# Abblix.SharedSignals.MinimalApi

ASP.NET Core Minimal API integration for [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals): the OpenID Shared Signals Framework 1.0 endpoints as route handlers, with no MVC dependency.

## Transmitter

```csharp
builder.Services
    .AddSecurityEvents(options => options.SigningKeySource = ...)
    .AddSsfTransmitter(new SsfTransmitterOptions
    {
        Issuer = "https://tr.example.com",
        EventsSupported = ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
        PollEndpointFactory = streamId => new Uri($"https://tr.example.com/ssf/poll/{streamId}"),
        JwksUri = new Uri("https://tr.example.com/.well-known/jwks.json"),
    });

var app = builder.Build();
app.MapSsfTransmitterEndpoints("/ssf").RequireAuthorization("ssf-receivers");
```

One call maps the whole management surface under the prefix - streams, status, subjects, verification, poll delivery - plus the configuration document at the well-known address the issuer resolves to. The well-known endpoint stays outside the returned group on purpose: discovery must answer before any receiver has credentials, so the authorization you attach to the group does not cover it.

Receivers are told apart by identity: the endpoints read it from the authenticated principal (the `sub` claim, then the identity name), and `SsfEndpointOptions.ReceiverIdSelector` replaces that mapping when the host's authentication carries the identity elsewhere.

## Receiver

```csharp
builder.Services
    .AddSecurityEvents()
    .AddJwksKeyResolution()
    .AddDistributedReplayCache()
    .AddSsfReceiver(new SsfValidationOptions
    {
        ExpectedAudience = "https://receiver.example.com",
        ExpectedIssuers = ["https://tr.example.com"],
        StreamIssuer = "https://tr.example.com",
    })
    .AddSingleton<ISecurityEventSink, MyEventSink>();

var app = builder.Build();
app.MapSsfPushEndpoint("/events");
```

The push endpoint answers the empty 202 or the 400 whose body speaks the RFC 8935 registry vocabulary; where accepted events land is the host's `ISecurityEventSink`.

## License

Abblix.SharedSignals.MinimalApi is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).
