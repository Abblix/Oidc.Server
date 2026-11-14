// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.TokenExchange;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the grant handlers the token endpoint dispatches on, built-in and host-supplied.
/// </summary>
public static class AuthorizationGrantServiceCollectionExtensions
{
    /// <summary>
    /// Enables support for the password grant type, acknowledging its security considerations.
    /// </summary>
    /// <remarks>
    /// This method is intentionally separated from the standard OIDC core service registration due to the inherent
    /// security risks associated with the password grant type. The password grant type requires the client to handle
    /// user credentials directly, which can increase the risk of credential exposure and related security issues.
    /// By isolating this method, we ensure that developers make a deliberate decision to enable this feature, being
    /// fully aware of its security implications. It's recommended to use more secure grant types like authorization
    /// code or client credentials whenever possible. Call this before <c>AddOidcCore</c>/<c>AddOidcServices</c>:
    /// the password grant handler must be registered before the grant handlers are composed, otherwise the
    /// registration is rejected at startup.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the password grant handler to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection EnablePasswordGrant(this IServiceCollection services)
    {
        return services.AddAuthorizationGrant<PasswordGrantHandler>();
    }

    /// <summary>
    /// Registers services required for JWT Bearer grant type, including JWT Bearer issuer provider,
    /// JWT replay prevention cache, and keyed caching decorator for JWKS fetching.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddJwtBearerGrant(this IServiceCollection services)
    {
        services.TryAddSingleton<IJwtBearerIssuerProvider, JwtBearerIssuerProvider>();

        // The storage lives in Abblix.JWT so a Security Event Token receiver can share it without
        // reaching for the OpenID Connect server.
        services.AddReplayPrevention();

        return services.AddAuthorizationGrant<JwtBearerGrantHandler>();
    }

    /// <summary>
    /// Registers the authorization code grant handler for OAuth 2.0 authorization code flow.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationCodeGrant(this IServiceCollection services)
    {
        return services.AddAuthorizationGrant<AuthorizationCodeGrantHandler>();
    }

    /// <summary>
    /// Registers the refresh token grant handler for OAuth 2.0 refresh token flow.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddRefreshTokenGrant(this IServiceCollection services)
    {
        return services.AddAuthorizationGrant<RefreshTokenGrantHandler>();
    }

    /// <summary>
    /// Registers the client credentials grant handler for OAuth 2.0 client credentials flow.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddClientCredentialsGrant(this IServiceCollection services)
    {
        return services.AddAuthorizationGrant<ClientCredentialsGrantHandler>();
    }

    /// <summary>
    /// Registers the RFC 8693 Token Exchange grant handler together with the per-type
    /// <see cref="Features.TokenExchange.ISubjectTokenResolver"/> implementations the library
    /// ships natively (JWT-formatted subject tokens via <see cref="Features.TokenExchange.JwtSubjectTokenResolver"/>
    /// for the <c>access_token</c>/<c>id_token</c>/<c>jwt</c> type URIs, and
    /// <see cref="Features.TokenExchange.RefreshTokenSubjectTokenResolver"/> for refresh tokens).
    /// </summary>
    /// <remarks>
    /// Opt-in: unlike the authorization-code, refresh-token and client-credentials grants, this one is
    /// not registered by <c>AddTokenEndpoint</c>. Call it explicitly, and call it BEFORE
    /// <c>AddOidcCore</c> / <c>AddOidcServices</c> / <c>AddOidcMinimalApi</c>, because
    /// <c>AddAuthorizationGrants()</c> composes the registered handlers inside them - a handler added
    /// afterwards lands beside the composite and the token endpoint resolves the wrong single
    /// <see cref="Token.Grants.IAuthorizationGrantHandler"/>. A host that does not call this
    /// neither serves the grant nor advertises it in <c>grant_types_supported</c>.
    ///
    /// Subject-token resolvers are dispatched by keyed DI under the
    /// <c>urn:ietf:params:oauth:token-type:*</c> URI. Hosts may register additional resolvers
    /// after this call (e.g. SAML 2.0 assertions in federation scenarios) - the handler picks
    /// them up automatically.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddTokenExchangeGrant(this IServiceCollection services)
    {
        // JwtSubjectTokenResolver is stateless and serves three token-type URIs from one
        // instance -- registered once as a singleton and re-exposed under three keyed entries
        // via factory delegates. RefreshTokenSubjectTokenResolver has its own dependencies
        // (IRefreshTokenService) so it is registered directly as a keyed singleton.
        services.TryAddSingleton<JwtSubjectTokenResolver>();
        services.TryAddKeyedSingleton<ISubjectTokenResolver>(
            TokenExchangeTokenTypes.AccessToken,
            (sp, _) => sp.GetRequiredService<JwtSubjectTokenResolver>());
        services.TryAddKeyedSingleton<ISubjectTokenResolver>(
            TokenExchangeTokenTypes.IdToken,
            (sp, _) => sp.GetRequiredService<JwtSubjectTokenResolver>());
        services.TryAddKeyedSingleton<ISubjectTokenResolver>(
            TokenExchangeTokenTypes.Jwt,
            (sp, _) => sp.GetRequiredService<JwtSubjectTokenResolver>());
        services.TryAddKeyedSingleton<ISubjectTokenResolver, RefreshTokenSubjectTokenResolver>(
            TokenExchangeTokenTypes.RefreshToken);

        return services.AddAuthorizationGrant<TokenExchangeGrantHandler>();
    }

    /// <summary>
    /// Composes all registered authorization grant handlers into a composite handler and registers it as the grant type informer.
    /// This method should be called after all individual grant handlers have been registered.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationGrants(this IServiceCollection services)
    {
        return services
            .Compose<IAuthorizationGrantHandler, CompositeAuthorizationGrantHandler>()
            .AddAlias<IGrantTypeInformer, CompositeAuthorizationGrantHandler>()
            .AddTelemetryDecorator<IAuthorizationGrantHandler, ObservedAuthorizationGrantHandler>();
    }

    /// <summary>
    /// Registers <typeparamref name="TImpl"/> as both <see cref="IAuthorizationGrantHandler"/>
    /// (for grant-handling dispatch via <see cref="CompositeAuthorizationGrantHandler"/>) and
    /// <see cref="IGrantTypeInformer"/> (for discovery and registration-time gates that
    /// aggregate the full <c>grant_types_supported</c> set across all informers). Every
    /// <see cref="IAuthorizationGrantHandler"/> implementation, both built-in and host-supplied,
    /// must be registered through this helper so the dual-presence invariant cannot be silently
    /// missed when a new grant handler is added.
    /// </summary>
    /// <typeparam name="TImpl">The concrete grant-handler implementation to register.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationGrant<TImpl>(this IServiceCollection services)
        where TImpl : class, IAuthorizationGrantHandler
    {
        // Fail loud when a grant handler is registered after AddOidcCore has composed the handlers. Compose registers
        // CompositeAuthorizationGrantHandler as a concrete service and removes the individual
        // IAuthorizationGrantHandler registrations, so its presence marks that composition already happened: a handler
        // added now lands beside the composite rather than inside it, and the token endpoint would silently not
        // dispatch its grant type. The opt-in that registers the handler must run before AddOidcCore.
        if (services.Any(descriptor => descriptor.ServiceType == typeof(CompositeAuthorizationGrantHandler)))
        {
            throw new InvalidOperationException(
                $"The authorization grant handler '{typeof(TImpl).Name}' is registered after the grant handlers were " +
                "composed by AddOidcCore/AddOidcServices. Registered this late it lands beside the composite the token " +
                "endpoint dispatches on rather than inside it, so its grant type would be silently unavailable. Call " +
                "the opt-in that registers this handler (for example AddDeviceAuthorization, " +
                "AddBackChannelAuthentication or EnablePasswordGrant) BEFORE AddOidcCore/AddOidcServices.");
        }

        services.TryAddSingleton<TImpl>();
        services.TryAddEnumerableAlias<IAuthorizationGrantHandler, TImpl>();
        services.TryAddEnumerableAlias<IGrantTypeInformer, TImpl>();
        return services;
    }
}
