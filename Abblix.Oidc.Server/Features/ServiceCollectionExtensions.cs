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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.GrantProcessors;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.UserInfo;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http;
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
            .AddSingleton<IClientAuthenticator, ClientSecretJwtAuthenticator>()
            .AddSingleton<IClientAuthenticator, PrivateKeyJwtAuthenticator>()
            // mTLS self-signed client authentication per RFC 8705
            .AddSingleton<IClientAuthenticator, TlsClientAuthenticator>()
            // mTLS metadata-driven subject/SAN matching (tls_client_auth)
            .AddSingleton<IClientAuthenticator, TlsMetadataClientAuthenticator>()
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
    /// Registers common services required by the application, like system clock, hashing services, etc.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> with the common services registered.</returns>
    public static IServiceCollection AddCommonServices(this IServiceCollection services)
    {
        services.TryAddSingleton<IUserConsentsProvider, NullConsentService>();
        services.Decorate<IUserConsentsProvider, PromptConsentDecorator>();

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IHashService, HashService>();
        services.AddKeyedSingleton<IBinarySerializer, JsonBinarySerializer>(nameof(JsonBinarySerializer));
        services.AddKeyedSingleton<IBinarySerializer, ProtobufSerializer>(nameof(ProtobufSerializer));
        services.TryAddSingleton<IBinarySerializer, CompositeBinarySerializer>();
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
            .AddScoped<IIdentityTokenService, IdentityTokenService>();
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
    /// Registers services for validating and formatting JWTs used in client authentication scenarios within
    /// the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <remarks>
    /// This method adds services to the <see cref="IServiceCollection"/> that are responsible for validating and
    /// formatting JWTs used specifically in client authentication.
    /// These services ensure that JWTs conform to the required standards,
    /// include all necessary claims, and are properly validated for client authentication processes.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the client JWT validation and
    /// formatting services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further service registrations.</returns>
    public static IServiceCollection AddClientJwt(this IServiceCollection services)
    {
        return services
            .AddSingleton<IClientJwtValidator, ClientJwtValidator>()
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
    /// Registers services for various storage functionalities related to the OAuth 2.0 and OpenID Connect flows within
    /// the application. This method configures essential storage services that manage authorization codes and
    /// authorization requests, ensuring their persistence and accessibility across the application.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to which the storage services will be added.
    /// This collection is crucial for configuring dependency injection in ASP.NET Core applications, allowing services
    /// to be added, managed, and retrieved throughout the application lifecycle.</param>
    /// <returns>The modified <see cref="IServiceCollection"/> after adding the storage services, permitting additional
    /// configurations to be chained.</returns>
    public static IServiceCollection AddStorages(this IServiceCollection services)
    {
        services.TryAddSingleton<IEntityStorageKeyFactory, EntityStorageKeyFactory>();
        services.TryAddSingleton<IAuthorizationCodeService, AuthorizationCodeService>();
        services.TryAddSingleton<IAuthorizationRequestStorage, AuthorizationRequestStorage>();
        return services;
    }

    /// <summary>
    /// Registers services related to user claims management into the provided <see cref="IServiceCollection"/>.
    /// This method sets up essential services required for processing and handling user claims based on authentication
    /// sessions and authorization requests, facilitating the integration of user-specific data into tokens or responses.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to which the user claims provider services will be
    /// added. This collection is a mechanism for adding and retrieving dependencies in .NET applications, often used
    /// to configure dependency injection in ASP.NET Core applications.</param>
    /// <returns>The updated <see cref="IServiceCollection"/> after adding the services, allowing for further
    /// modifications and additions to be chained.</returns>
    public static IServiceCollection AddUserInfo(this IServiceCollection services)
    {
        services.TryAddScoped<IUserClaimsProvider, UserClaimsProvider>();
        services.TryAddSingleton<ISubjectTypeConverter, SubjectTypeConverter>();
        services.TryAddSingleton<IScopeClaimsProvider, ScopeClaimsProvider>();
        services.TryAddSingleton<IScopeManager, ScopeManager>();
        services.TryAddSingleton<IResourceManager, ResourceManager>();
        return services;
    }

    /// <summary>
    /// Adds request object fetching capabilities to the dependency injection container.
    /// Registers services required for processing JWT request objects, including their validation
    /// and binding to the appropriate request properties.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to which the user claims provider services will be
    /// added. This collection is a mechanism for adding and retrieving dependencies in .NET applications, often used
    /// to configure dependency injection in ASP.NET Core applications.</param>
    /// <returns>The updated <see cref="IServiceCollection"/> after adding the services, allowing for further
    /// modifications and additions to be chained.</returns>
    public static IServiceCollection AddRequestObject(this IServiceCollection services)
    {
        services.TryAddScoped<IRequestObjectFetcher, RequestObjectFetcher>();
        return services;
    }

    /// <summary>
    /// Configures services for handling back-channel authentication requests, enabling secure server-to-server
    /// authentication flows and registers the CIBA grant handler.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddBackChannelAuthentication(this IServiceCollection services)
    {
        services.TryAddSingleton<IUserDeviceAuthenticationHandler, UserDeviceAuthenticationHandlerStub>();
        services.TryAddSingleton<IAuthenticationRequestIdGenerator, AuthenticationRequestIdGenerator>();
        services.TryAddSingleton<IBackChannelRequestStorage, BackChannelRequestStorage>();
        services.TryAddSingleton<INotificationDeliveryService, HttpNotificationDeliveryService>();

        // Register mode-specific completion handlers as keyed services
        services.TryAddKeyedScoped<AuthenticationCompletionHandler, PollModeCompletionHandler>(BackchannelTokenDeliveryModes.Poll);
        services.TryAddKeyedScoped<AuthenticationCompletionHandler, PingModeCompletionHandler>(BackchannelTokenDeliveryModes.Ping);
        services.TryAddKeyedScoped<AuthenticationCompletionHandler, PushModeCompletionHandler>(BackchannelTokenDeliveryModes.Push);

        // Register router that automatically selects the appropriate mode-specific handler
        services.TryAddScoped<IAuthenticationCompletionHandler, AuthenticationCompletionRouter>();

        // Register mode-specific grant processors as keyed services
        services.TryAddKeyedSingleton<IBackChannelGrantProcessor, PollModeGrantProcessor>(BackchannelTokenDeliveryModes.Poll);
        services.TryAddKeyedSingleton<IBackChannelGrantProcessor, PingModeGrantProcessor>(BackchannelTokenDeliveryModes.Ping);
        services.TryAddKeyedSingleton<IBackChannelGrantProcessor, PushModeGrantProcessor>(BackchannelTokenDeliveryModes.Push);

        // Register long-polling status notifier if long-polling is enabled
        // This service is optional - if not registered, long-polling will be disabled
        services.TryAddSingleton<IBackChannelLongPollingService>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<OidcOptions>>();
            if (options.Value.BackChannelAuthentication.UseLongPolling)
            {
                var logger = sp.GetRequiredService<ILogger<InMemoryLongPollingService>>();
                return new InMemoryLongPollingService(logger);
            }
            return null!;
        });

        // Register HTTP client for backchannel notifications (ping and push modes) with configurable handler lifetime
        // Use configuration callback to get handler lifetime from OidcOptions
        services.AddOptions<HttpClientFactoryOptions>(nameof(HttpNotificationDeliveryService))
            .Configure<IOptions<OidcOptions>>((httpOptions, oidcOptions) =>
            {
                httpOptions.HandlerLifetime = oidcOptions.Value.BackChannelAuthentication.NotificationHttpClientHandlerLifetime;
            });

        services.AddHttpClient(nameof(HttpNotificationDeliveryService));

        // Register CIBA grant handler
        services.AddSingleton<IAuthorizationGrantHandler, BackChannelAuthenticationGrantHandler>();

        return services;
    }

    /// <summary>
    /// Configures services for handling Device Authorization Grant (RFC 8628) requests,
    /// enabling devices with limited input capabilities to obtain user authorization.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddDeviceAuthorization(this IServiceCollection services)
    {
        services.TryAddSingleton<IDeviceCodeGenerator, DeviceCodeGenerator>();
        services.TryAddSingleton<IUserCodeGenerator, UserCodeGenerator>();
        services.TryAddSingleton<IDeviceAuthorizationStorage, DeviceAuthorizationStorage>();
        services.TryAddSingleton<IUserCodeRateLimiter, UserCodeRateLimiter>();
        services.TryAddSingleton<IUserCodeVerificationService, UserCodeVerificationService>();

        // Register Device Authorization grant handler
        services.AddSingleton<IAuthorizationGrantHandler, DeviceCodeGrantHandler>();

        return services;
    }

    /// <summary>
    /// Registers secure HTTP fetching services with SSRF (Server-Side Request Forgery) protection.
    /// This method configures the HTTP client for fetching external content (such as sector identifier URIs
    /// and request URIs) and decorates it with validation to prevent SSRF attacks.
    /// </summary>
    /// <remarks>
    /// The registered services include:
    /// - A typed HTTP client (<see cref="SecureHttpFetcher"/>) for making secure HTTP requests
    /// - A custom message handler (<see cref="SsrfValidatingHttpMessageHandler"/>) that provides comprehensive SSRF protection
    ///
    /// The SSRF protection includes:
    /// - Blocking requests to internal hostnames (localhost, internal, etc.)
    /// - Blocking requests to internal TLDs (.local, .internal, etc.)
    /// - DNS resolution and blocking of private/reserved IP address ranges
    /// - Re-validation of DNS before HTTP request to prevent DNS rebinding attacks (TOCTOU)
    /// - HTTP redirect disabling to prevent redirect-based SSRF bypass
    /// - Response size and timeout limits (configurable via <see cref="SecureHttpFetchOptions"/>)
    ///
    /// The multi-layered protection strategy follows OWASP SSRF Prevention guidelines and provides
    /// defense-in-depth against various SSRF attack vectors including DNS rebinding and redirect-based bypasses.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <param name="configure">Optional configuration action to customize <see cref="SecureHttpFetchOptions"/>.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddSecureHttpFetch(
        this IServiceCollection services,
        Action<SecureHttpFetchOptions>? configure = null)
    {
        // Register and configure options
        var optionsBuilder = services.AddOptions<SecureHttpFetchOptions>();

        if (configure != null)
        {
            optionsBuilder.Configure(configure);
        }

        services
            .AddSingleton<SsrfValidatingHttpMessageHandler>()
            .AddHttpClient<ISecureHttpFetcher, SecureHttpFetcher>((serviceProvider, client) =>
            {
                var options = serviceProvider.GetRequiredService<IOptions<SecureHttpFetchOptions>>().Value;
                client.Timeout = options.RequestTimeout;
            })
            .ConfigurePrimaryHttpMessageHandler<SsrfValidatingHttpMessageHandler>();

        return services;
    }
}
