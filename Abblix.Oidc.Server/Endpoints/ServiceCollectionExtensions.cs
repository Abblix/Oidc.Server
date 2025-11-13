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
using Abblix.Oidc.Server.Endpoints.CheckSession;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;


namespace Abblix.Oidc.Server.Endpoints;

public static class ServiceCollectionExtensions
{
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
        return services
            .AddAuthorizationRequestFetchers()
            .AddAuthorizationContextValidators()
            .AddScoped<AuthorizationHandler>()
            .AddAlias<IAuthorizationHandler, AuthorizationHandler>()
            .AddAlias<IGrantTypeInformer, AuthorizationHandler>()
            .AddScoped<IAuthorizationRequestValidator, AuthorizationRequestValidator>()
            .AddScoped<IAuthorizationRequestProcessor, AuthorizationRequestProcessor>();
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
        return services
            // Add a JSON object binder as a singleton
            .AddSingleton<IJsonObjectBinder, JsonSerializationBinder>()

            // Add individual authorization request fetchers as singletons
            .AddScoped<IAuthorizationRequestFetcher, PushedRequestFetcher>()
            .AddScoped<IAuthorizationRequestFetcher, RequestUriFetcher>()
            .AddScoped<IAuthorizationRequestFetcher, Authorization.RequestFetching.RequestObjectFetchAdapter>()

            // Compose the individual fetchers into a composite fetcher
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
        return services
            // compose AuthorizationContext validation as a pipeline of several IAuthorizationContextValidator
            .AddSingleton<IAuthorizationContextValidator, Authorization.Validation.ClientValidator>()
            .AddSingleton<IAuthorizationContextValidator, RedirectUriValidator>()
            .AddSingleton<IAuthorizationContextValidator, FlowTypeValidator>()
            .AddSingleton<IAuthorizationContextValidator, ResponseModeValidator>()
            .AddSingleton<IAuthorizationContextValidator, NonceValidator>()
            .AddSingleton<IAuthorizationContextValidator, Authorization.Validation.ResourceValidator>()
            .AddSingleton<IAuthorizationContextValidator, Authorization.Validation.ScopeValidator>()
            .AddSingleton<IAuthorizationContextValidator, PkceValidator>()
            .Compose<IAuthorizationContextValidator, AuthorizationContextValidatorComposite>();
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
        return services
            .AddScoped<IPushedAuthorizationHandler, PushedAuthorizationHandler>(
                Dependency.Override<IAuthorizationRequestFetcher, Authorization.RequestFetching.RequestObjectFetchAdapter>())
            .AddScoped<IPushedAuthorizationRequestValidator, PushedAuthorizationRequestValidator>()
            .AddScoped<IPushedAuthorizationRequestProcessor, PushedAuthorizationRequestProcessor>();
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
            .AddAuthorizationGrants()
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
        return services
            // Register individual validators that will participate in a composite pattern.
            .AddSingleton<ITokenContextValidator, Token.Validation.ResourceValidator>()
            .AddSingleton<ITokenContextValidator, Token.Validation.ScopeValidator>()
            .AddSingleton<ITokenContextValidator, Token.Validation.ClientValidator>()
            .AddSingleton<ITokenContextValidator, AuthorizationGrantValidator>()
            // Combine all registered ITokenContextValidator into a single composite validator.
            // This composite approach allows the application to apply multiple validation checks sequentially.
            .Compose<ITokenContextValidator, TokenContextValidatorComposite>();
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
        return services
            .AddSingleton<IAuthorizationGrantHandler, PasswordGrantHandler>();
    }

    /// <summary>
    /// Adds services for validating and processing revocation requests. This capability is essential for OAuth 2.0
    /// compliance, enabling clients to revoke access or refresh tokens when they are no longer needed or
    /// if a security issue arises, thus minimizing the potential for unauthorized use of tokens.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationGrants(this IServiceCollection services)
    {
        return services
            .AddSingleton<IAuthorizationGrantHandler, AuthorizationCodeGrantHandler>()
            .AddSingleton<IAuthorizationGrantHandler, RefreshTokenGrantHandler>()
            .AddSingleton<IAuthorizationGrantHandler, BackChannelAuthenticationGrantHandler>()
            .AddSingleton<IAuthorizationGrantHandler, ClientCredentialsGrantHandler>()
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
        return services
            .AddScoped<IRevocationHandler, RevocationHandler>()
            .AddScoped<IRevocationRequestValidator, RevocationRequestValidator>()
            .AddScoped<IRevocationRequestProcessor, RevocationRequestProcessor>();
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
        return services
            .AddScoped<IIntrospectionHandler, IntrospectionHandler>()
            .AddScoped<IIntrospectionRequestValidator, IntrospectionRequestValidator>()
            .AddScoped<IIntrospectionRequestProcessor, IntrospectionRequestProcessor>();
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
        return services
            .AddScoped<ICheckSessionHandler, CheckSessionHandler>();
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
        return services
            .AddScoped<IUserInfoHandler, UserInfoHandler>()
            .AddScoped<IUserInfoRequestValidator, UserInfoRequestValidator>()
            .AddScoped<IUserInfoRequestProcessor, UserInfoRequestProcessor>();
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
        return services
            .AddClientRegistrationContextValidators()

            .AddSingleton<IRegistrationAccessTokenValidator, RegistrationAccessTokenValidator>()
            .AddTransient(newClientOptionsFactory)

            .AddScoped<IClientCredentialFactory, ClientCredentialFactory>()
            .AddScoped<IRegistrationAccessTokenService, RegistrationAccessTokenService>()

            .AddScoped<IRegisterClientHandler, RegisterClientHandler>()
            .AddScoped<IRegisterClientRequestValidator, RegisterClientRequestValidator>()
            .AddScoped<IRegisterClientRequestProcessor, RegisterClientRequestProcessor>()

            .AddScoped<IClientRequestValidator, ClientRequestValidator>()

            .AddScoped<IReadClientHandler, ReadClientHandler>()
            .AddScoped<IReadClientRequestProcessor, ReadClientRequestProcessor>()

            .AddScoped<IRemoveClientHandler, RemoveClientHandler>()
            .AddScoped<IRemoveClientRequestProcessor, RemoveClientRequestProcessor>();
    }

    private static IServiceCollection AddClientRegistrationContextValidators(this IServiceCollection services)
    {
        return services
                // compose ClientRegistrationContext validation as a pipeline of several IClientRegistrationContextValidator
                .AddSingleton<IClientRegistrationContextValidator, ClientIdValidator>()
                .AddSingleton<IClientRegistrationContextValidator, RedirectUrisValidator>()
                .AddSingleton<IClientRegistrationContextValidator, DynamicClientManagement.Validation.PostLogoutRedirectUrisValidator>()
                .AddSingleton<IClientRegistrationContextValidator, GrantTypeValidator>()
                .AddSingleton<IClientRegistrationContextValidator, SubjectTypeValidator>()
                .AddSingleton<IClientRegistrationContextValidator, InitiateLoginUriValidator>()
                .AddSingleton<IClientRegistrationContextValidator, BackChannelAuthenticationValidator>()
                .AddSingleton<IClientRegistrationContextValidator, SigningAlgorithmsValidator>()
                .AddSingleton<IClientRegistrationContextValidator, SignedResponseAlgorithmsValidator>()
                .AddSingleton<IClientRegistrationContextValidator, TokenEndpointAuthMethodValidator>()
                .AddSingleton<IClientRegistrationContextValidator, TlsClientAuthValidator>()
                .Compose<IClientRegistrationContextValidator, ClientRegistrationContextValidatorComposite>();
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
        return services
                .AddEndSessionContextValidators()
                .AddScoped<IEndSessionHandler, EndSessionHandler>()
                .AddScoped<IEndSessionRequestValidator, EndSessionRequestValidator>()
                .AddScoped<IEndSessionRequestProcessor, EndSessionRequestProcessor>();
    }

    public static IServiceCollection AddEndSessionContextValidators(this IServiceCollection services)
    {
        return services
            .AddSingleton<IEndSessionContextValidator, IdTokenHintValidator>()
            .AddSingleton<IEndSessionContextValidator, EndSession.Validation.ClientValidator>()
            .AddSingleton<IEndSessionContextValidator, EndSession.Validation.PostLogoutRedirectUrisValidator>()
            .AddSingleton<IEndSessionContextValidator, ConfirmationValidator>()
            .Compose<IEndSessionContextValidator, EndSessionContextValidatorComposite>();
    }

    /// <summary>
    /// Configures services for handling back-channel authentication requests, enabling secure server-to-server
    /// authentication flows.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddBackChannelAuthenticationEndpoint(this IServiceCollection services)
    {
        return services
            .AddBackChannelAuthenticationContextValidators()

            .AddScoped<IBackChannelAuthenticationRequestFetcher, BackChannelAuthentication.RequestFetching.RequestObjectFetchAdapter>()
            .AddScoped<IBackChannelAuthenticationHandler, BackChannelAuthenticationHandler>()
            .AddScoped<IBackChannelAuthenticationRequestValidator, BackChannelAuthenticationRequestValidator>()
            .AddScoped<IBackChannelAuthenticationRequestProcessor, BackChannelAuthenticationRequestProcessor>();
    }

    public static IServiceCollection AddBackChannelAuthenticationContextValidators(this IServiceCollection services)
    {
        return services
            // compose BackChannelAuthenticationValidationContext validation as a pipeline of several IBackChannelAuthenticationContextValidator
            .AddSingleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ClientValidator>()
            .AddSingleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ResourceValidator>()
            .AddSingleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ScopeValidator>()
            .AddSingleton<IBackChannelAuthenticationContextValidator, UserIdentityValidator>()
            .AddSingleton<IBackChannelAuthenticationContextValidator, RequestedExpiryValidator>()
            .AddSingleton<IBackChannelAuthenticationContextValidator, UserCodeValidator>()
            .Compose<IBackChannelAuthenticationContextValidator, BackChannelAuthenticationValidatorComposite>();
    }
}
