// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Endpoints.Token;
using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the token endpoint and the validation pipeline every token request passes through.
/// </summary>
public static class TokenEndpointServiceCollectionExtensions
{
    /// <summary>
    /// Adds services for validating and processing token requests according to OAuth 2.0 and OpenID Connect
    /// standards. This setup supports various grant types, ensuring that token requests are handled securely and
    /// efficiently, facilitating the issuance of access tokens, refresh tokens, and ID tokens to clients.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddTokenEndpoint(this IServiceCollection services)
    {
        services
            .AddJwtBearerGrant()
            .AddAuthorizationCodeGrant()
            .AddRefreshTokenGrant()
            .AddClientCredentialsGrant()
            // TokenExchangeGrantHandler is registered in AddTokenExchangeGrant(), like
            // BackChannelAuthenticationGrantHandler in AddBackChannelAuthentication() and
            // DeviceCodeGrantHandler in AddDeviceAuthorization(). Token exchange is opt-in because
            // registering it makes the OP advertise urn:ietf:params:oauth:grant-type:token-exchange
            // in grant_types_supported, and a host that never intends to delegate authority should
            // not publish that it does. It also brings four subject-token resolvers, one of which
            // (RefreshTokenSubjectTokenResolver) reads the refresh-token store.
            // AddAuthorizationGrants() is called in AddOidcCore() after all handlers are registered
            .AddTokenContextValidators();

         services.TryAddScoped<ITokenAuthorizationContextEvaluator, TokenAuthorizationContextEvaluator>();

         services.TryAddScoped<ITokenHandler, TokenHandler>();
         services.AddTelemetryDecorator<ITokenHandler, ObservedTokenHandler>();
         services.TryAddScoped<ITokenRequestValidator, TokenRequestValidator>();
         services.TryAddScoped<ITokenRequestProcessor, TokenRequestProcessor>();
         services.Decorate<ITokenRequestProcessor, AuthorizationCodeReusePreventingDecorator>();
         services.AddTelemetryDecorator<ITokenRequestProcessor, MeasuredTokenRequestProcessor>();

         return services;
    }

    /// <summary>
    /// Configures and registers a composite of token context validators into the service collection.
    /// This method sets up a sequence of validators that perform various checks on token requests,
    /// ensuring they comply with the necessary criteria before a token can be issued.
    /// </summary>
    /// <param name="services">The service collection to which the token context validators will be added.</param>
    /// <returns>The modified service collection with the registered token context validators.</returns>
    public static IServiceCollection AddTokenContextValidators(this IServiceCollection services)
    {
        // Register individual validators that will participate in a composite pattern.
        // Order is load-bearing:
        // - ClientValidator must precede DPoPTokenEndpointValidator because the latter reads
        //   ClientInfo.RequireDPoP to decide whether DPoP is mandatory or opportunistic.
        // - ClientValidator must also precede ScopeValidator: ScopeValidator enforces the client's
        //   registered scope set and therefore reads ClientInfo, which ClientValidator populates.
        // - AuthorizationGrantValidator must precede RevokedSessionValidator, which reads the AuthSession
        //   the former resolves. It also has to stay in validation rather than move into the processor:
        //   the authorization code is spent by a decorator around the processor, so a refusal there would
        //   burn a code the request never earned.
        // - The device code and the backchannel authentication request are spent INSIDE
        //   AuthorizationGrantValidator, so what can refuse without the grant runs before it:
        //   DPoPTokenEndpointValidator, whose nonce challenge RFC 9449 section 8 answers with a retry that
        //   must still find the grant. DPoPBindingValidator reads the grant and follows it.
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<ITokenContextValidator, Token.Validation.ResourceValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, Token.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, Token.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, DPoPTokenEndpointValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, AuthorizationGrantValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, Token.Validation.RevokedSessionValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, DPoPBindingValidator>()
        ]);
        // Combine all registered ITokenContextValidator into a single composite validator.
        // This composite approach allows the application to apply multiple validation checks sequentially.
        return services.Compose<ITokenContextValidator, TokenContextValidatorComposite>();
    }
}
