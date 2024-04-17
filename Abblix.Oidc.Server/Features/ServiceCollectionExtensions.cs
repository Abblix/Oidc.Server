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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring OpenID Connect (OIDC) server services.
/// </summary>
public static class ServiceCollectionExtensions
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
        return services
            .AddSingleton<IClientAuthenticator, NoneClientAuthenticator>()
            .AddSingleton<IClientAuthenticator, ClientSecretPostAuthenticator>()
            .AddSingleton<IClientAuthenticator, ClientSecretBasicAuthenticator>()
            //.AddSingleton<IClientRequestAuthenticator, ClientSecretJwtAuthenticator>() //TODO support and uncomment
            .AddSingleton<IClientAuthenticator, PrivateKeyJwtAuthenticator>()
            .Compose<IClientAuthenticator, CompositeClientAuthenticator>();
    }

    /// <summary>
    /// Configures services related to client information management. This includes registering the client information storage mechanism,
    /// which serves as the provider and manager for client information, as well as the provider for client keys. This setup is crucial
    /// for the OIDC server to manage and validate client identities and their corresponding secrets or keys.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddClientInformation(this IServiceCollection services)
    {
        return services
            .AddSingleton<ClientInfoStorage>()
            .AddAlias<IClientInfoProvider, ClientInfoStorage>()
            .AddAlias<IClientInfoManager, ClientInfoStorage>()
            .AddSingleton<IClientKeysProvider, ClientKeysProvider>();
    }

    /// <summary>
    /// Registers common services required by the application, like system clock, hashing services etc.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> with the common services registered.</returns>
    public static IServiceCollection AddCommonServices(this IServiceCollection services)
    {
        services.TryAddSingleton<IConsentService, NullConsentService>();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IHashService, HashService>();
        services.TryAddSingleton<ISubjectTypeConverter, SubjectTypeConverter>();
        services.TryAddSingleton<IScopeClaimsProvider, ScopeClaimsProvider>();
        services.TryAddSingleton<IBinarySerializer, Utf8JsonBinarySerializer>();
        services.TryAddSingleton<IEntityStorage, DistributedCacheStorage>();
        return services.AddJsonWebTokens();
    }

    /// <summary>
    /// Configures the issuer provider service to dynamically determine the issuer URI based on application settings.
    /// If an issuer is preconfigured in the options, a preconfigured issuer provider is used.
    /// Otherwise, a request-based issuer provider is utilized to determine the issuer URI dynamically,
    /// allowing for flexible deployment scenarios.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the issuer provider to.</param>
    /// <returns>The modified <see cref="IServiceCollection"/> with the issuer provider configured.</returns>
    public static IServiceCollection AddIssuer(this IServiceCollection services)
    {
        return services
            .AddSingleton<IIssuerProvider>(sp =>
            {
                var options = sp.GetRequiredService<IOptions<OidcOptions>>().Value;
                return options.Issuer != null
                    ? sp.CreateService<PreconfiguredIssuerProvider>()
                    : sp.CreateService<RequestBasedIssuerProvider>();
            });
    }

    /// <summary>
    /// Configures services for logout notification mechanisms within the application. This method
    /// sets up both front-channel and back-channel logout capabilities, allowing the application to notify
    /// clients about logout events through direct user agent redirection or server-to-server communication, respectively.
    /// It integrates a composite logout notifier that aggregates both mechanisms to provide a unified approach to logout notifications.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the logout notification services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddLogoutNotification(this IServiceCollection services)
    {
        return services
            .AddFrontChannelLogout()
            .AddBackChannelLogout()
            .Compose<ILogoutNotifier, CompositeLogoutNotifier>();
    }

    /// <summary>
    /// Adds the necessary services for back-channel logout functionality to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    public static IServiceCollection AddBackChannelLogout(this IServiceCollection services)
    {
        return services
            .AddScoped<ILogoutNotifier, BackChannelLogoutNotifier>()
            .AddSingleton<ILogoutTokenService, LogoutTokenService>()
            .AddHttpClient<ILogoutTokenSender, BackChannelLogoutTokenSender>()
            .Services;
    }

    /// <summary>
    /// Adds the necessary services for front-channel logout functionality to the specified <see cref="IServiceCollection"/>.
    /// Front-channel logout is typically used for web-based applications where the logout request is sent directly from
    /// the user's browser to the identity provider and other logged-in services.
    /// </summary>
    public static IServiceCollection AddFrontChannelLogout(this IServiceCollection services)
    {
        return services
            .AddScoped<ILogoutNotifier, FrontChannelLogoutNotifier>();
    }

    /// <summary>
    /// Adds singleton services for generating random client IDs, client secrets, token IDs, and session IDs
    /// to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    public static IServiceCollection AddRandomGenerators(this IServiceCollection services)
    {
        services.TryAddSingleton<IAuthorizationCodeGenerator, AuthorizationCodeGenerator>();
        services.TryAddSingleton<IAuthorizationRequestUriGenerator, AuthorizationRequestUriGenerator>();
        services.TryAddSingleton<IClientIdGenerator, ClientIdGenerator>();
        services.TryAddSingleton<IClientSecretGenerator, ClientSecretGenerator>();
        services.TryAddSingleton<ITokenIdGenerator, TokenIdGenerator>();
        services.TryAddSingleton<ISessionIdGenerator, SessionIdGenerator>();
        return services;
    }

    /// <summary>
    /// Adds services related to session management and decorates the authorization request processor within
    /// the specified <see cref="IServiceCollection"/>.
    /// </summary>
    public static IServiceCollection AddSessionManagement(this IServiceCollection services)
    {
        return services
            .AddScoped<ISessionManagementService, SessionManagementService>()
            .Decorate<IAuthorizationRequestProcessor, AuthorizationRequestProcessorDecorator>();
    }

    /// <summary>
    /// Configures token services including token creation, authentication, client-specific JWT handling, and
    /// token revocation within the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <remarks>
    /// This method aggregates the setup of multiple services related to tokens, enhancing the application's security
    /// infrastructure by providing comprehensive support for JWT (JSON Web Tokens) and token lifecycle management.
    ///
    /// It includes the configuration of:
    /// - General token services for managing the creation and validation of tokens.
    /// - Authentication services that leverage JWT for securing user authentication processes.
    /// - Client JWT services, tailored for handling JWTs in client-specific contexts.
    /// - Token revocation services to facilitate the process of invalidating tokens when necessary,
    /// such as during logout or when a security breach is detected.
    ///
    /// The integration of these services ensures a robust and scalable approach to handling tokens,
    /// which are critical for secure communication and access control within modern web applications.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure with token-related services.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddTokenServices(this IServiceCollection services)
    {
        return services
            .AddAccessToken()
            .AddRefreshToken()
            .AddIdentityToken()
            .AddAuthServiceJwt()
            .AddClientJwt()
            .AddTokenRevocation();
    }


    /// <summary>
    /// This method adds a service that manages the lifecycle of refresh tokens, including their creation,
    /// validation, and revocation. Refresh tokens are used to obtain new access tokens without requiring
    /// the user to re-authenticate, enhancing the user experience by providing seamless session continuity.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure with token-related services.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddRefreshToken(this IServiceCollection services)
    {
        return services
            .AddSingleton<IRefreshTokenService, RefreshTokenService>();
    }

    /// <summary>
    /// This method adds a service responsible for generating, validating, and managing access tokens.
    /// Access tokens are crucial for securing API endpoints, as they provide a mechanism to verify that
    /// a request is authorized to access specific resources.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure with token-related services.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddAccessToken(this IServiceCollection services)
    {
        return services
            .AddSingleton<IAccessTokenService, AccessTokenService>();
    }

    /// <summary>
    /// This method adds a service that handles identity tokens, which are used to convey the identity of
    /// the authenticated user to the application. Identity tokens typically contain claims about the user,
    /// such as their name or role, which can be used for user interface customization and access control decisions.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure with token-related services.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddIdentityToken(this IServiceCollection services)
    {
        return services
            .AddSingleton<IIdentityTokenService, IdentityTokenService>();
    }

    /// <summary>
    /// Registers JWT formatting and validation services for authentication within the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the JWT authentication services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further service registrations.</returns>
    public static IServiceCollection AddAuthServiceJwt(this IServiceCollection services)
    {
        return services
            .AddSingleton<IAuthServiceKeysProvider, OidcOptionsKeysProvider>()

            .AddSingleton<IAuthServiceJwtFormatter, AuthServiceJwtFormatter>()
            .AddSingleton<IAuthServiceJwtValidator, AuthServiceJwtValidator>();
    }

    /// <summary>
    /// Registers a service for formatting JWTs specific to client authentication within the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <remarks>
    /// Adds a service which provides functionality for formatting JWTs used in client authentication scenarios.
    /// This service ensures that JWTs generated for clients adhere to the required format and contain all necessary
    /// claims for identifying and authenticating users in the client application.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the client JWT formatting service to.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further service registrations.</returns>
    public static IServiceCollection AddClientJwt(this IServiceCollection services)
    {
        return services
            .AddSingleton<IClientJwtFormatter, ClientJwtFormatter>();
    }

    /// <summary>
    /// Decorates the JSON Web Token validator service with a token status validator to support token revocation
    /// within the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <remarks>
    /// This method enhances the application's security by decorating the <see cref="IJsonWebTokenValidator"/> service
    /// with <see cref="TokenStatusValidatorDecorator"/>.
    /// This decoration adds the capability to check the revocation status of tokens, allowing the application to reject
    /// tokens that have been revoked. This is crucial for maintaining the integrity and security of the application's
    /// authentication system, particularly in response to security incidents or user logout events.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add token revocation support to.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further service registrations.</returns>
    public static IServiceCollection AddTokenRevocation(this IServiceCollection services)
    {
        return services
            .Decorate<IJsonWebTokenValidator, TokenStatusValidatorDecorator>()
            .AddSingleton<ITokenRegistry, TokenRegistry>();
    }

    /// <summary>
    /// Registers the license JWT provider using options configuration to obtain the license JWT.
    /// </summary>
    /// <remarks>
    /// This method configures the OIDC service's licensing by using the <see cref="OptionsLicenseJwtProvider"/>,
    /// which retrieves the license JWT from application settings or options. It's suitable for scenarios where
    /// the license JWT is configured through application settings (e.g., appsettings.json or environment variables).
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the license provider to.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further configurations.</returns>
    public static IServiceCollection AddLicenseFromOptions(this IServiceCollection services)
    {
        return services
            .AddHostedService<LicenseLoadingService>()
            .AddSingleton<ILicenseJwtProvider, OptionsLicenseJwtProvider>();
    }

    /// <summary>
    /// Registers the license JWT provider using a provided static license JWT string.
    /// </summary>
    /// <remarks>
    /// This method allows for direct specification of the license JWT, bypassing options configuration.
    /// It utilizes the <see cref="StaticLicenseJwtProvider"/> to supply the license JWT directly to the OIDC service.
    /// This approach is particularly useful in scenarios where the license JWT is obtained programmatically or from
    /// external sources not tied to the application's static configuration.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the license provider to.</param>
    /// <param name="licenseJwt">The license JWT string to be used for OIDC service configuration validation.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further configurations.</returns>
    public static IServiceCollection AddLicense(this IServiceCollection services, string licenseJwt)
    {
        return services
            .AddHostedService<LicenseLoadingService>()
            .AddSingleton<ILicenseJwtProvider, StaticLicenseJwtProvider>(Dependency.Override(licenseJwt));
    }

    /// <summary>
    /// Adds singleton services related to storage mechanisms to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddStorages(this IServiceCollection services)
    {
        services.TryAddSingleton<IAuthorizationCodeService, AuthorizationCodeService>();
        services.TryAddSingleton<IAuthorizationRequestStorage, AuthorizationRequestStorage>();
        return services;
    }
}
