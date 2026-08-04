# Abblix.SharedSignals

The transport and management layer of the [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
for .NET, built on [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents):
transmitter and receiver in one package.

The package is under construction on this branch; the README grows with the surface.

- Transmitter: configuration discovery (`/.well-known/ssf-configuration`), event stream
  management, subjects and verification, push (RFC 8935) and poll (RFC 8936) delivery.
- Receiver: stream registration against any conformant transmitter, push reception with
  idempotent processing, poll client.

## License

Abblix.SharedSignals is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).
