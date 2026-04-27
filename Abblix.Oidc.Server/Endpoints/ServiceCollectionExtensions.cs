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
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Endpoints.CheckSession;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
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
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;


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
        services.TryAddScoped<IJwtAlgorithmsProvider, JwtAlgorithmsProvider>();
        services.TryAddScoped<IAcrMetadataProvider, AcrMetadataProvider>();
        services.TryAddScoped<IConfigurationHandler, ConfigurationHandler>();
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
        services.TryAddScoped<IAuthorizationRequestProcessor, AuthorizationRequestProcessor>();

        return services
            .AddAlias<IAuthorizationHandler, AuthorizationHandler>()
            .AddAlias<IGrantTypeInformer, AuthorizationHandler>();
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
        services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Scoped<IAuthorizationRequestFetcher, PushedRequestFetcher>(),
            ServiceDescriptor.Scoped<IAuthorizationRequestFetcher, RequestUriFetcher>(),
            ServiceDescriptor.Scoped<IAuthorizationRequestFetcher, Authorization.RequestFetching.RequestObjectFetchAdapter>(),
        });

        // Compose the individual fetchers into a composite fetcher
        return services
            .Compose<IAuthorizationRequestFetcher, Authorization.RequestFetching.CompositeRequestFetcher>();
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
        services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, Authorization.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, RedirectUriValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, FlowTypeValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, ResponseModeValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, NonceValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, Authorization.Validation.ResourceValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, Authorization.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, PkceValidator>(),
        });
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
            // BackChannelAuthenticationGrantHandler and DeviceCodeGrantHandler are registered
            // in AddBackChannelAuthentication() and AddDeviceAuthorization() respectively
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
        services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<ITokenContextValidator, Token.Validation.ResourceValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, Token.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, Token.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<ITokenContextValidator, AuthorizationGrantValidator>(),
        });
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
    /// code or client credentials whenever possible.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the password grant handler to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection EnablePasswordGrant(this IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationGrantHandler, PasswordGrantHandler>());
        return services;
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

        // Register keyed caching decorator for JWT Bearer JWKS fetching
        // DecorateKeyed will find the non-keyed ISecureHttpFetcher and create a keyed decorated version
        services.DecorateKeyed<ISecureHttpFetcher, CachingSecureHttpFetcherDecorator>(
            JwtBearerIssuerProvider.SecureHttpFetcherKey);

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationGrantHandler, JwtBearerGrantHandler>());

        return services;
    }

    /// <summary>
    /// Registers the authorization code grant handler for OAuth 2.0 authorization code flow.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationCodeGrant(this IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationGrantHandler, AuthorizationCodeGrantHandler>());
        return services;
    }

    /// <summary>
    /// Registers the refresh token grant handler for OAuth 2.0 refresh token flow.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddRefreshTokenGrant(this IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationGrantHandler, RefreshTokenGrantHandler>());
        return services;
    }

    /// <summary>
    /// Registers the client credentials grant handler for OAuth 2.0 client credentials flow.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddClientCredentialsGrant(this IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationGrantHandler, ClientCredentialsGrantHandler>());
        return services;
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
    /// Adds services for validating and processing revocation requests. This capability is essential for OAuth 2.0
    /// compliance, enabling clients to revoke access or refresh tokens when they are no longer needed or if
    /// a security issue arises, thus minimizing the potential for unauthorized use of tokens.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddRevocationEndpoint(this IServiceCollection services)
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
    public static IServiceCollection AddIntrospectionEndpoint(this IServiceCollection services)
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
    public static IServiceCollection AddCheckSessionEndpoint(this IServiceCollection services)
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
    public static IServiceCollection AddDynamicClientEndpoints(
        this IServiceCollection services,
        Func<IServiceProvider, NewClientOptions> newClientOptionsFactory)
    {
        services
            .AddClientRegistrationContextValidators()
            .AddDefaultInitialAccessTokenRevocationProvider();

        services.TryAddSingleton<IRegistrationAccessTokenValidator, RegistrationAccessTokenValidator>();
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
        services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, InitialAccessTokenValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, ClientIdValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, RedirectUrisValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, DynamicClientManagement.Validation.PostLogoutRedirectUrisValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, GrantTypeValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, DynamicClientManagement.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SoftwareStatementValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SubjectTypeValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, InitiateLoginUriValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, BackChannelAuthenticationValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SigningAlgorithmsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SignedResponseAlgorithmsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, TokenEndpointAuthMethodValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, CredentialsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, TlsClientAuthValidator>(),
        });
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

    public static IServiceCollection AddEndSessionContextValidators(this IServiceCollection services)
    {
        services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<IEndSessionContextValidator, IdTokenHintValidator>(),
            ServiceDescriptor.Singleton<IEndSessionContextValidator, EndSession.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<IEndSessionContextValidator, EndSession.Validation.PostLogoutRedirectUrisValidator>(),
            ServiceDescriptor.Singleton<IEndSessionContextValidator, ConfirmationValidator>(),
        });
        return services.Compose<IEndSessionContextValidator, EndSessionContextValidatorComposite>();
    }

    /// <summary>
    /// Configures services for handling back-channel authentication requests, enabling secure server-to-server
    /// authentication flows.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddBackChannelAuthenticationEndpoint(this IServiceCollection services)
    {
        services.AddBackChannelAuthenticationContextValidators();

        services.TryAddScoped<IBackChannelAuthenticationRequestFetcher, BackChannelAuthentication.RequestFetching.RequestObjectFetchAdapter>();
        services.TryAddScoped<IBackChannelAuthenticationHandler, BackChannelAuthenticationHandler>();
        services.TryAddScoped<IBackChannelAuthenticationRequestValidator, BackChannelAuthenticationRequestValidator>();
        services.TryAddScoped<IBackChannelAuthenticationRequestProcessor, BackChannelAuthenticationRequestProcessor>();

        return services;
    }

    public static IServiceCollection AddBackChannelAuthenticationContextValidators(this IServiceCollection services)
    {
        // compose BackChannelAuthenticationValidationContext validation as a pipeline of several IBackChannelAuthenticationContextValidator
        services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ResourceValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, UserIdentityValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, RequestedExpiryValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, UserCodeValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, PingModeValidator>(),
        });
        return services.Compose<IBackChannelAuthenticationContextValidator, BackChannelAuthenticationValidatorComposite>();
    }

    /// <summary>
    /// Configures services for handling Device Authorization Grant (RFC 8628) requests,
    /// enabling devices with limited input capabilities to obtain user authorization.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddDeviceAuthorizationEndpoint(this IServiceCollection services)
    {
        services.AddDeviceAuthorizationContextValidators();
        services.TryAddScoped<IDeviceAuthorizationHandler, DeviceAuthorizationHandler>();
        services.TryAddScoped<IDeviceAuthorizationRequestValidator, DeviceAuthorizationRequestValidator>();
        services.TryAddScoped<IDeviceAuthorizationRequestProcessor, DeviceAuthorizationRequestProcessor>();
        return services;
    }

    public static IServiceCollection AddDeviceAuthorizationContextValidators(this IServiceCollection services)
    {
        services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorization.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorization.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorization.Validation.ResourceValidator>(),
        });
        return services.Compose<IDeviceAuthorizationContextValidator, DeviceAuthorizationValidatorComposite>();
    }
}
