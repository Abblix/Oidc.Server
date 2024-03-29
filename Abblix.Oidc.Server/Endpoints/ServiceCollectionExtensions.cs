// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
using Abblix.Oidc.Server.Endpoints.UserInfo;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using ClientValidator = Abblix.Oidc.Server.Endpoints.Authorization.Validation.ClientValidator;
using PostLogoutRedirectUrisValidator = Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation.PostLogoutRedirectUrisValidator;

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
            .AddScoped<IAuthorizationHandler, AuthorizationHandler>()
            .AddScoped<IAuthorizationRequestValidator, AuthorizationRequestValidator>()
            .AddScoped<IAuthorizationRequestProcessor, AuthorizationRequestProcessor>();
    }

    public static IServiceCollection AddAuthorizationRequestFetchers(this IServiceCollection services)
    {
        return services
            .AddSingleton<IAuthorizationRequestFetcher, PushedRequestFetcher>()
            .AddSingleton<IAuthorizationRequestFetcher, RequestUriFetcher>()
            .AddSingleton<IJsonObjectBinder, JsonSerializationBinder>()
            .AddSingleton<IAuthorizationRequestFetcher, RequestObjectFetcher>()
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
        return services
            // compose AuthorizationContext validation as a pipeline of several IAuthorizationContextValidator
            .AddSingleton<IAuthorizationContextValidator, ClientValidator>()
            .AddSingleton<IAuthorizationContextValidator, RedirectUriValidator>()
            .AddSingleton<IAuthorizationContextValidator, FlowTypeValidator>()
            .AddSingleton<IAuthorizationContextValidator, ResponseModeValidator>()
            .AddSingleton<IAuthorizationContextValidator, NonceValidator>()
            .AddSingleton<IAuthorizationContextValidator, ScopeValidator>()
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
            .AddScoped<IPushedAuthorizationHandler, PushedAuthorizationHandler>()
            .AddScoped<IPushedAuthorizationRequestValidator, PushedAuthorizationRequestValidator>(
                Dependency.Override<IAuthorizationRequestFetcher, RequestObjectFetcher>())
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
        return services
            .AddAuthorizationGrants()

            .AddScoped<ITokenHandler, TokenHandler>()
            .AddScoped<ITokenRequestValidator, TokenRequestValidator>()
            .AddScoped<ITokenRequestProcessor, TokenRequestProcessor>()
            .Decorate<ITokenRequestProcessor, AuthorizationCodeReusePreventingDecorator>();
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
            .Compose<IAuthorizationGrantHandler, CompositeAuthorizationGrantHandler>();
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
                .AddSingleton<IClientRegistrationContextValidator, PostLogoutRedirectUrisValidator>()
                .AddSingleton<IClientRegistrationContextValidator, GrantTypeValidator>()
                .AddSingleton<IClientRegistrationContextValidator, SubjectTypeValidator>()
                .AddSingleton<IClientRegistrationContextValidator, InitiateLoginUriValidator>()
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
            .AddSingleton<IEndSessionContextValidator, Abblix.Oidc.Server.Endpoints.EndSession.Validation.ClientValidator>()
            .AddSingleton<IEndSessionContextValidator, Abblix.Oidc.Server.Endpoints.EndSession.Validation.PostLogoutRedirectUrisValidator>()
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
            .AddScoped<IBackChannelAuthenticationRequestValidator, BackChannelAuthenticationRequestValidator>()
            .AddScoped<IBackChannelAuthenticationRequestProcessor, BackChannelAuthenticationRequestProcessor>()
            .AddScoped<IBackChannelAuthenticationStorage, BackChannelAuthenticationStorage>();
    }
}