// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Endpoints.CheckSession;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Endpoints.EndSession;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Endpoints.Introspection;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Revocation;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Endpoints.UserInfo;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Oidc.Server.Features.PushedAuthorization;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using CompositeRequestFetcher = Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching.CompositeRequestFetcher;
using DistributedJwtReplayCache = Abblix.Oidc.Server.Features.ReplayPrevention.DistributedJwtReplayCache;
using IJwtReplayCache = Abblix.Oidc.Server.Features.ReplayPrevention.IJwtReplayCache;
using JwtBearer = Abblix.Oidc.Server.Features.JwtBearer;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Extension methods that register endpoint pipelines (handler + validator + processor + per-step
/// validators / fetchers / grant handlers) for the OAuth 2.0 / OpenID Connect endpoints exposed by
/// this library: configuration, authorization (with PAR), token, userinfo, revocation, introspection,
/// check-session, end-session, dynamic client management, CIBA backchannel and RFC 8628 device
/// authorization. Use <c>TryAdd*</c> so that host pre-registrations win.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the configuration handler for OpenID Connect Discovery endpoint.
    /// </summary>
    /// <remarks>
    /// This handler builds discovery metadata according to OpenID Connect Discovery specification,
    /// providing framework-agnostic metadata about the provider's configuration.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddConfigurationEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IAuthorizationMetadataProvider, AuthorizationMetadataProvider>();
        services.TryAddScoped<IScopesAndClaimsProvider, ScopesAndClaimsProvider>();
        // Singleton, unlike its scoped neighbours: JwtAlgorithmsProvider is a stateless projection over the
        // singleton IJsonWebTokenCreator/IJsonWebTokenValidator, so scoping it would only make it a captive
        // dependency of the singleton client-registration validators (SigningAlgorithmsValidator and
        // SignedResponseAlgorithmsValidator) that consume it.
        services.TryAddSingleton<IJwtAlgorithmsProvider, JwtAlgorithmsProvider>();
        services.TryAddScoped<IAcrMetadataProvider, AcrMetadataProvider>();
        services.TryAddScoped<IConfigurationHandler, ConfigurationHandler>();
        // Scoped to match the adapters' response formatters, which are the only consumers and are themselves
        // scoped: the signature is produced per request over that request's resolved endpoint URLs.
        services.TryAddScoped<ISignedMetadataProvider, SignedMetadataProvider>();
        return services;
    }

    /// <summary>
    /// Adds services and processors for handling authorization requests to the service collection.
    /// </summary>
    /// <remarks>
    /// This setup is crucial for supporting the OAuth 2.0 and OpenID Connect authorization flow,
    /// ensuring that incoming authorization requests are correctly validated and processed.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationEndpoint(this IServiceCollection services)
    {
        services
            .AddAuthorizationRequestFetchers()
            .AddAuthorizationContextValidators();

        services.TryAddScoped<AuthorizationHandler>();
        services.TryAddScoped<IAuthorizationRequestValidator, AuthorizationRequestValidator>();
        services.TryAddSingleton<IConsentConstraintEnforcer, ConsentConstraintEnforcer>();
        services.TryAddScoped<IAuthorizationRequestProcessor, AuthorizationRequestProcessor>();

        // Single-use PAR (RFC 9126 §7.3): decorate the processor so a pushed request_uri is consumed once a
        // terminal success has minted a code or token. Mirrors the session-management decorator and stacks
        // with it; both act independently on a SuccessfullyAuthenticated outcome.
        services.Decorate<IAuthorizationRequestProcessor, PushedAuthorizationRequestProcessorDecorator>();

        // Response encoding (iss/scope gating + JARM packing) lives in the framework-agnostic core and
        // runs from the handler after the full processing chain. Scoped: it reads per-request issuer state.
        services.TryAddScoped<IAuthorizationResponseEncoder, AuthorizationResponseEncoder>();

        // Authorization Code Flow is registered by default. Implicit / Hybrid Flow components
        // (token, id_token response processors) are registered only when the host calls
        // EnableImplicitFlow(); without that call those response types are not in the DI graph
        // and the authorization endpoint rejects them per OAuth 2.1 (draft) deprecation guidance.
        services.AddAuthorizationResponseProcessor<AuthorizationCodeBuilder>();

        // AuthorizationHandler is no longer aliased as IGrantTypeInformer: each registered
        // IAuthorizationResponseBuilder now contributes its own grant types directly to the
        // IGrantTypeInformer set, so the IGrantTypeInformer chain stays Singleton-friendly
        // (every contributor is Singleton - no captive-dep risk for Singleton consumers).
        // TryAddAlias keeps the host-first contract on this seam (issue #226).
        return services.TryAddAlias<IAuthorizationHandler, AuthorizationHandler>();
    }

    /// <summary>
    /// Registers authorization request fetchers and related services into the provided IServiceCollection.
    /// This method adds implementations for various authorization request fetchers as singletons, ensuring
    /// that they are efficiently reused throughout the application. It also composes these fetchers into a
    /// composite fetcher to handle different types of authorization requests seamlessly.
    /// </summary>
    /// <param name="services">The IServiceCollection to which the services will be added.</param>
    /// <returns>The updated IServiceCollection with the added authorization request fetchers.</returns>
    public static IServiceCollection AddAuthorizationRequestFetchers(this IServiceCollection services)
    {
        // Add a JSON object binder as a singleton
        services.TryAddSingleton<IJsonObjectBinder, JsonSerializationBinder>();

        // Add individual authorization request fetchers as enumerable strategy set
        services.TryAddEnumerable([
            ServiceDescriptor.Scoped<IAuthorizationRequestFetcher, PushedRequestFetcher>(),
            ServiceDescriptor.Scoped<IAuthorizationRequestFetcher, RequestUriFetcher>(),
            ServiceDescriptor.Scoped<IAuthorizationRequestFetcher, Authorization.RequestFetching.RequestObjectFetchAdapter>()
        ]);

        // Compose the individual fetchers into a composite fetcher
        return services
            .Compose<IAuthorizationRequestFetcher, CompositeRequestFetcher>();
    }

    /// <summary>
    /// Adds a series of validators for authorization context as a composite service to ensure comprehensive validation
    /// of authorization requests.
    /// </summary>
    /// <remarks>
    /// This method composes a pipeline of validators for various aspects of the authorization context,
    /// such as request object validation, client validation, and more.
    /// This composite validator approach enables modular and extensible validation logic, ensuring that
    /// authorization requests meet all necessary criteria and standards.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationContextValidators(this IServiceCollection services)
    {
        // compose AuthorizationContext validation as a pipeline of several IAuthorizationContextValidator
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, Authorization.Validation.ClientValidator>(),
            // Right after ClientValidator: needs the resolved ClientInfo and must reject plain
            // parameters from a require_signed_request_object client before further processing.
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, SignedRequestObjectRequirementValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, RedirectUriValidator>(),
            // Scoped: FlowTypeValidator consumes IEnumerable<IAuthorizationResponseBuilder>, which
            // includes the scoped IdTokenResponseBuilder once EnableImplicitFlow() is called.
            ServiceDescriptor.Scoped<IAuthorizationContextValidator, FlowTypeValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, ResponseModeValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, NonceValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, Authorization.Validation.ResourceValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, Authorization.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, PkceValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, ProofKeyThumbprintValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, AuthorizationDetailsRequestValidator>()
        ]);
        return services.Compose<IAuthorizationContextValidator, AuthorizationContextValidatorComposite>();
    }

    /// <summary>
    /// Registers validators and processors for pushed authorization requests (PAR), enhancing the security and
    /// efficiency of the authorization process by allowing clients to send requests directly to
    /// the authorization server via a back-channel connection.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddPushedAuthorizationEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IPushedAuthorizationHandler>(sp => sp.CreateService<PushedAuthorizationHandler>(
            Dependency.Override<IAuthorizationRequestFetcher, Authorization.RequestFetching.RequestObjectFetchAdapter>()));
        services.TryAddScoped<IPushedAuthorizationRequestValidator, PushedAuthorizationRequestValidator>();
        services.TryAddScoped<IPushedAuthorizationRequestProcessor, PushedAuthorizationRequestProcessor>();
        return services;
    }

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
         services.TryAddScoped<ITokenRequestValidator, TokenRequestValidator>();
         services.TryAddScoped<ITokenRequestProcessor, TokenRequestProcessor>();
         services.Decorate<ITokenRequestProcessor, AuthorizationCodeReusePreventingDecorator>();

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
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<ITokenContextValidator, Token.Validation.ResourceValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, Token.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, Token.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, AuthorizationGrantValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, DPoPTokenEndpointValidator>()
        ]);
        // Combine all registered ITokenContextValidator into a single composite validator.
        // This composite approach allows the application to apply multiple validation checks sequentially.
        return services.Compose<ITokenContextValidator, TokenContextValidatorComposite>();
    }

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
        services.TryAddSingleton<IJwtReplayCache, DistributedJwtReplayCache>();

        // The replay-cache implementation now lives in Features.ReplayPrevention so DPoP
        // and any future consumer can share it. The JwtBearer-namespaced shim is the
        // singleton registered concretely; both the canonical interface and the deprecated
        // JwtBearer.IJwtReplayCache alias resolve to the same instance for back-compat.
#pragma warning disable CS0618 // intentional registration of the deprecated shim
        services.TryAddSingleton<JwtBearer.IJwtReplayCache, JwtBearer.DistributedJwtReplayCache>();
#pragma warning restore CS0618

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
            .AddAlias<IGrantTypeInformer, CompositeAuthorizationGrantHandler>();
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

    /// <summary>
    /// Registers <typeparamref name="TImpl"/> as a Singleton concrete service and aliases the
    /// SAME instance under both <see cref="IAuthorizationResponseBuilder"/> (for response-type
    /// dispatch in the authorization endpoint) and <see cref="IGrantTypeInformer"/> (for
    /// discovery and registration-time gates that aggregate <c>grant_types_supported</c>).
    /// Every <see cref="IAuthorizationResponseBuilder"/> implementation must be registered
    /// through this helper so each processor's declared grant type lands in the
    /// <see cref="IGrantTypeInformer"/> chain without an extra registration step.
    /// </summary>
    /// <typeparam name="TImpl">The concrete response-builder implementation to register.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <param name="lifetime">The service lifetime for the processor and its aliases; defaults to
    /// <see cref="ServiceLifetime.Singleton"/>. Use <see cref="ServiceLifetime.Scoped"/> when the
    /// processor has scoped dependencies, to avoid a captive dependency.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationResponseProcessor<TImpl>(
        this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TImpl : class, IAuthorizationResponseBuilder
    {
        // The IAuthorizationResponseBuilder / IGrantTypeInformer aliases inherit this lifetime
        // (BuildAliasDescriptor preserves the source lifetime), so a builder with scoped
        // dependencies registers Scoped and its aliases follow - no captive dependency.
        services.TryAdd(new ServiceDescriptor(typeof(TImpl), typeof(TImpl), lifetime));
        services.TryAddEnumerableAlias<IAuthorizationResponseBuilder, TImpl>();
        services.TryAddEnumerableAlias<IGrantTypeInformer, TImpl>();
        return services;
    }

    /// <summary>
    /// Adds services for validating and processing revocation requests. This capability is essential for OAuth 2.0
    /// compliance, enabling clients to revoke access or refresh tokens when they are no longer needed or if
    /// a security issue arises, thus minimizing the potential for unauthorized use of tokens.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddRevocationEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IRevocationHandler, RevocationHandler>();
        services.TryAddScoped<IRevocationRequestValidator, RevocationRequestValidator>();
        services.TryAddScoped<IRevocationRequestProcessor, RevocationRequestProcessor>();
        return services;
    }

    /// <summary>
    /// Adds validators and processors for introspection requests, enabling resource servers to verify the active status
    /// of tokens and access token metadata. This feature is crucial for applications that need to validate tokens
    /// coming from different clients or issued by external authorization servers.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddIntrospectionEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IIntrospectionHandler, IntrospectionHandler>();
        services.TryAddScoped<IIntrospectionRequestValidator, IntrospectionRequestValidator>();
        services.TryAddScoped<IIntrospectionRequestProcessor, IntrospectionRequestProcessor>();
        return services;
    }

    /// <summary>
    /// Registers services for handling check session requests, facilitating session management in compliance with
    /// OpenID Connect session management standards.
    /// </summary>
    /// <remarks>
    /// Adds a scoped service for processing check session requests, allowing clients to query the authentication status
    /// of the user in an iframe. This is part of the OpenID Connect session management specification,
    /// enabling applications to maintain a consistent user session state across different clients and
    /// the identity provider. It supports functionalities for clients to detect when a user's session has ended
    /// at the identity provider, prompting for re-authentication or logout as necessary.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure with check session endpoint support.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>, enabling further chaining of service registrations.</returns>
    internal static IServiceCollection AddCheckSessionEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<ICheckSessionHandler, CheckSessionHandler>();
        return services;
    }

    /// <summary>
    /// Adds services for handling user info requests, allowing clients to retrieve claims about the authenticated user
    /// in accordance with OpenID Connect standards.
    /// </summary>
    /// <remarks>
    /// Registers scoped validators and processors for user info requests, enabling the secure delivery of claims
    /// about the authenticated session user to the client. This functionality is crucial for OpenID Connect-compliant
    /// applications, providing a standardized method for clients to access user profile information based on the scopes
    /// and permissions granted during authentication. The service setup ensures that user info requests are properly
    /// validated and processed, safeguarding sensitive user information while supporting rich client applications.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure with user info endpoint capabilities.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>, allowing for further service registration chaining.</returns>
     public static IServiceCollection AddUserInfoEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IUserInfoHandler, UserInfoHandler>();
        services.TryAddScoped<IUserInfoRequestValidator, UserInfoRequestValidator>();
        services.TryAddScoped<IUserInfoRequestProcessor, UserInfoRequestProcessor>();
        services.TryAddSingleton<IDPoPUserInfoValidator, UserInfo.Validation.DPoPUserInfoValidator>();
        services.TryAddSingleton<IMtlsUserInfoValidator, UserInfo.Validation.MtlsUserInfoValidator>();
        return services;
    }

    /// <summary>
    /// Registers services and validators for dynamic client registration and management endpoints,
    /// based on the provided options factory.
    /// </summary>
    /// <remarks>
    /// This method enables the dynamic registration, reading, and removal of OAuth 2.0 clients at runtime,
    /// facilitating flexible and scalable client management.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <param name="newClientOptionsFactory">A factory function to setup options for new client registrations.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddDynamicClientEndpoints(
        this IServiceCollection services,
        Func<IServiceProvider, NewClientOptions> newClientOptionsFactory)
    {
        services
            .AddClientRegistrationContextValidators()
            .AddDefaultInitialAccessTokenRevocationProvider();

        services.TryAddSingleton<IRegistrationAccessTokenValidator, RegistrationAccessTokenValidator>();
        services.TryAddScoped<IRegistrationAccessTokenStore, RegistrationAccessTokenStore>();
        services.TryAddTransient(newClientOptionsFactory);

        services.TryAddScoped<IClientCredentialFactory, ClientCredentialFactory>();
        services.TryAddScoped<IRegistrationAccessTokenService, RegistrationAccessTokenService>();
        services.TryAddScoped<IInitialAccessTokenService, InitialAccessTokenService>();

        services.TryAddScoped<IRegisterClientHandler, RegisterClientHandler>();
        services.TryAddScoped<IRegisterClientRequestValidator, RegisterClientRequestValidator>();
        services.TryAddKeyedScoped<IRegisterClientRequestValidator, UpdateClientRegistrationValidator>(UpdateClientRequestValidator.RegistrationKey);
        services.TryAddScoped<IRegisterClientRequestProcessor, RegisterClientRequestProcessor>();

        services.TryAddScoped<IClientRequestValidator, ClientRequestValidator>();

        services.TryAddScoped<IReadClientHandler, ReadClientHandler>();
        services.TryAddScoped<IReadClientRequestProcessor, ReadClientRequestProcessor>();

        services.TryAddScoped<IUpdateClientHandler, UpdateClientHandler>();
        services.TryAddScoped<IUpdateClientRequestValidator, UpdateClientRequestValidator>();
        services.TryAddScoped<IUpdateClientRequestProcessor, UpdateClientRequestProcessor>();

        services.TryAddScoped<IRemoveClientHandler, RemoveClientHandler>();
        services.TryAddScoped<IRemoveClientRequestProcessor, RemoveClientRequestProcessor>();

        return services;
    }

    private static IServiceCollection AddDefaultInitialAccessTokenRevocationProvider(this IServiceCollection services)
    {
        services.TryAddSingleton<IInitialAccessTokenRevocationProvider, InitialAccessTokenRevocationProvider>();
        return services;
    }

    private static IServiceCollection AddClientRegistrationContextValidators(this IServiceCollection services)
    {
        // compose ClientRegistrationContext validation as a pipeline of several IClientRegistrationContextValidator
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, InitialAccessTokenValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, ClientIdValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, RedirectUrisValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, DynamicClientManagement.Validation.PostLogoutRedirectUrisValidator>(),
            // Server-level support gates run before the consistency check so the rejection message
            // surfaces "this server doesn't support that" rather than the more confusing
            // "your response_types/grant_types are inconsistent" from GrantTypeValidator.
            // Scoped: these gates consume IEnumerable<IAuthorizationResponseBuilder> /
            // IEnumerable<IGrantTypeInformer>, which include the scoped IdTokenResponseBuilder
            // once EnableImplicitFlow() is called.
            ServiceDescriptor.Scoped<IClientRegistrationContextValidator, SupportedResponseTypeValidator>(),
            ServiceDescriptor.Scoped<IClientRegistrationContextValidator, SupportedGrantTypeValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, GrantTypeValidator>(),
            // Fail-loud profile self-consistency: runs after the response/grant-type gates so an
            // unsupported or inconsistent type is reported as such before this surfaces a
            // profile-specific rejection.
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SecurityProfileValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, DynamicClientManagement.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SoftwareStatementValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SubjectTypeValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, InitiateLoginUriValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, BackChannelLogoutUriValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, BackChannelAuthenticationValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SigningAlgorithmsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SignedResponseAlgorithmsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, EncryptedResponseAlgorithmsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, TokenEndpointAuthMethodValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, CredentialsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, TlsClientAuthValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, AuthorizationDetailsTypesValidator>()
        ]);
        return services.Compose<IClientRegistrationContextValidator, ClientRegistrationContextValidatorComposite>();
    }

    /// <summary>
    /// Adds services for handling end session (logout) requests aligning with OpenID Connect session management
    /// specifications. This setup enables the application to handle logout requests effectively, ensuring that
    /// user sessions are terminated securely across all involved parties.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddEndSessionEndpoint(this IServiceCollection services)
    {
        services.AddEndSessionContextValidators();
        services.TryAddScoped<IEndSessionHandler, EndSessionHandler>();
        services.TryAddScoped<IEndSessionRequestValidator, EndSessionRequestValidator>();
        services.TryAddScoped<IEndSessionRequestProcessor, EndSessionRequestProcessor>();
        return services;
    }

    /// <summary>
    /// Configures and registers a composite of end-session context validators into the service
    /// collection. Validators run in sequence to verify the <c>id_token_hint</c>, the client,
    /// the post-logout redirect URI, and the confirmation claim before an end-session request
    /// is accepted.
    /// </summary>
    /// <param name="services">The service collection to which the end-session context validators will be added.</param>
    /// <returns>The modified service collection with the registered end-session context validators.</returns>
    public static IServiceCollection AddEndSessionContextValidators(this IServiceCollection services)
    {
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IEndSessionContextValidator, IdTokenHintValidator>(),
            ServiceDescriptor.Singleton<IEndSessionContextValidator, EndSession.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<IEndSessionContextValidator, EndSession.Validation.PostLogoutRedirectUrisValidator>(),
            ServiceDescriptor.Singleton<IEndSessionContextValidator, ConfirmationValidator>()
        ]);
        return services.Compose<IEndSessionContextValidator, EndSessionContextValidatorComposite>();
    }

    /// <summary>
    /// Configures services for handling back-channel authentication requests, enabling secure server-to-server
    /// authentication flows.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddBackChannelAuthenticationEndpoint(this IServiceCollection services)
    {
        services.AddBackChannelAuthenticationContextValidators();

        services.TryAddScoped<IBackChannelAuthenticationRequestFetcher, BackChannelAuthentication.RequestFetching.RequestObjectFetchAdapter>();
        services.TryAddScoped<IBackChannelAuthenticationHandler, BackChannelAuthenticationHandler>();
        services.TryAddScoped<IBackChannelAuthenticationRequestValidator, BackChannelAuthenticationRequestValidator>();
        services.TryAddScoped<IBackChannelAuthenticationRequestProcessor, BackChannelAuthenticationRequestProcessor>();

        return services;
    }

    /// <summary>
    /// Configures and registers a composite of back-channel authentication context validators
    /// into the service collection. Validators run in sequence to verify the client, the
    /// requested resources and scopes, the user identity hint, the requested expiry, the user
    /// code, and the ping-mode configuration before a CIBA request is accepted.
    /// </summary>
    /// <param name="services">The service collection to which the back-channel authentication context validators will be added.</param>
    /// <returns>The modified service collection with the registered back-channel authentication context validators.</returns>
    public static IServiceCollection AddBackChannelAuthenticationContextValidators(this IServiceCollection services)
    {
        // compose BackChannelAuthenticationValidationContext validation as a pipeline of several IBackChannelAuthenticationContextValidator
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ResourceValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, UserIdentityValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, RequestedExpiryValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, UserCodeValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, PingModeValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, PushModeValidator>(),
            // RFC 9396 §3 authorization_details on CIBA backchannel auth requests.
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthorizationDetailsValidator>(),
        ]);
        return services.Compose<IBackChannelAuthenticationContextValidator, BackChannelAuthenticationValidatorComposite>();
    }

    /// <summary>
    /// Registers the Device Authorization Grant (RFC 8628) endpoint services - handler, request and context
    /// validators, and the <c>DeviceAuthorizationOptionsValidator</c>. Invoked by the public
    /// <c>AddDeviceAuthorization()</c> opt-in method, not by the unconditional endpoint wiring: device
    /// authorization is a single opt-in feature, so its validator only runs when a server opts in.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddDeviceAuthorizationEndpoint(this IServiceCollection services)
    {
        services.AddDeviceAuthorizationContextValidators();
        services.TryAddScoped<IDeviceAuthorizationHandler, DeviceAuthorizationHandler>();
        services.TryAddScoped<IDeviceAuthorizationRequestValidator, DeviceAuthorizationRequestValidator>();
        services.TryAddScoped<IDeviceAuthorizationRequestProcessor, DeviceAuthorizationRequestProcessor>();

        // Fail loud at startup when the device endpoint is enabled but its settings are absent, instead of letting the
        // gap surface as an unhandled 500 on the first request. TryAddEnumerable because the options framework
        // resolves every registered IValidateOptions.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, DeviceAuthorizationOptionsValidator>());

        return services;
    }

    /// <summary>
    /// Configures and registers a composite of device authorization context validators into the
    /// service collection. Validators run in sequence to verify the client, the requested scopes,
    /// and the requested resources before a device authorization request (RFC 8628) is accepted.
    /// </summary>
    /// <param name="services">The service collection to which the device authorization context validators will be added.</param>
    /// <returns>The modified service collection with the registered device authorization context validators.</returns>
    public static IServiceCollection AddDeviceAuthorizationContextValidators(this IServiceCollection services)
    {
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorization.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorization.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorization.Validation.ResourceValidator>(),
            // RFC 9396 §3 authorization_details on device authorization requests.
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorizationDetailsValidator>(),
        ]);
        return services.Compose<IDeviceAuthorizationContextValidator, DeviceAuthorizationValidatorComposite>();
    }
}
