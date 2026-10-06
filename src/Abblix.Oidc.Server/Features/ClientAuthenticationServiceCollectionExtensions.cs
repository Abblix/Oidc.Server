// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.RateLimiting;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring client authentication.
/// </summary>
public static class ClientAuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Registers client authentication services with the provided <see cref="IServiceCollection"/>.
    /// This setup includes various authenticators for supporting different client authentication methods
    /// such as none, client secret post, client secret basic, private key JWT, and potentially others.
    /// It enables the application to handle client authentication according to the OAuth 2.0 and OpenID Connect standards.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the client authentication services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddClientAuthentication(this IServiceCollection services)
    {
        // Deliberate design: client authentication is a try-each composite, NOT keyed-name DI
        // by token_endpoint_auth_method. Unlike the keyed-DI extension points in this codebase
        // (signers by alg, RAR validators by type, crit handlers by name), the auth method is
        // NOT a discriminator carried in the incoming token request - it is the client's
        // registered metadata. The request only presents credentials whose FORM implies the
        // method (Basic header, body secret, mTLS certificate, client_assertion JWT), and
        // client_id itself is extracted method-specifically (decoded from the Base64 Basic
        // header vs read from the body vs taken from the assertion's sub). Keying on the method
        // would require first detecting the credential form to derive it - which is exactly what
        // each authenticator's TryAuthenticateClientAsync already does - so keyed dispatch would
        // be circular and strictly more complex. Each authenticator self-selects by inspecting
        // the request for its own credential shape; the composite returns the first match.
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IClientAuthenticator, NoneClientAuthenticator>(),
            ServiceDescriptor.Singleton<IClientAuthenticator, ClientSecretPostAuthenticator>(),
            ServiceDescriptor.Singleton<IClientAuthenticator, ClientSecretBasicAuthenticator>(),
            ServiceDescriptor.Singleton<IClientAuthenticator, ClientSecretJwtAuthenticator>(),
            ServiceDescriptor.Singleton<IClientAuthenticator, PrivateKeyJwtAuthenticator>(),
            // mTLS self-signed client authentication per RFC 8705
            ServiceDescriptor.Singleton<IClientAuthenticator, TlsClientAuthenticator>(),
            // mTLS metadata-driven subject/SAN matching (tls_client_auth)
            ServiceDescriptor.Singleton<IClientAuthenticator, TlsMetadataClientAuthenticator>()
        ]);

        // JWT assertion authenticators (client_secret_jwt / private_key_jwt) record assertion jti
        // values in the replay cache; called defensively so deployments that never call AddDPoP
        // or enable JWT Bearer still resolve the dependency.
        services.AddReplayPrevention();

        services.Compose<IClientAuthenticator, CompositeClientAuthenticator>();

        // Sees every client whichever credential form got it through. The configuration paths cannot: a client
        // registered dynamically before a profile was turned on lives in the store and is re-read by nobody.
        services.Decorate<IClientAuthenticator, SecurityProfileClientAuthenticator>();

        services.TryAddSingleton<AuthenticationFailureBudget>();
        services.TryAddSingleton<UnnamedSourceNotice>();

        // Registered with TryAdd, so a host that put its own limiter under this key keeps it - and then the
        // budget is live whatever the settings say, including while they say to count nothing.
        services.TryAddKeyedSingleton<PartitionedRateLimiter<string>>(
            CallerRateLimiters.AuthenticationFailures,
            (serviceProvider, _) => CallerRateLimiters.Create(
                serviceProvider.GetRequiredService<IOptions<OidcOptions>>().Value.AuthenticationFailureLimit));

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, CallerRateLimitOptionsValidator>());

        // Throttling outermost, so a source that has spent its budget of failures is refused before anything below
        // it looks at the credential - which for a signed assertion means before a signature is verified - the
        // stage's span included.
        return services
            .AddTelemetryDecorator<IClientAuthenticator, ObservedClientAuthenticator>()
            .Decorate<IClientAuthenticator, ThrottledClientAuthenticator>();
    }
}
