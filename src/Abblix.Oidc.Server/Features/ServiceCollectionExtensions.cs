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
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.GrantProcessors;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.ReusePrevention;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.ResponseObject;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.Nonces;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Features.ResourceIndicators;
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
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
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

        return services.Compose<IClientAuthenticator, CompositeClientAuthenticator>();
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
        services.TryAddSingleton<ClientInfoStorage>();
        services.TryAddSingleton<IClientKeysProvider, ClientKeysProvider>();

        // Fail loud at startup when a statically-configured client cannot satisfy its effective
        // security profile, instead of letting the contradiction surface per-request. TryAddEnumerable
        // because the options framework resolves every registered IValidateOptions.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, OidcOptionsSecurityProfileValidator>());

        // Fail loud at startup when a configured secret-bearing length is below the security floor
        // for its kind, instead of generating a guessable secret or an unusable HMAC key at runtime.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, SecretLengthOptionsValidator>());

        // Fail loud at startup when EnabledEndpoints advertises an opt-in endpoint whose feature services were
        // never registered by the matching AddX() call, instead of 500-ing on every request to it.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, EnabledEndpointsRegistrationValidator>());

        // Fail loud at startup when a ServiceTokens signing or encryption algorithm is not one the registered
        // signers/encryptors can produce, instead of failing per-request at token issuance.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ServiceTokensAlgorithmsValidator>());

        // Refuse a default resource indicator that no resource server could accept, rather than minting every
        // access token with an audience nothing recognises.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, DefaultResourceIndicatorValidator>());

        // TryAddAlias: a host that pre-registers its own client store must win over the
        // OidcOptions-backed default (issue #226) - same host-first contract as TryAdd* seams.
        return services
            .TryAddAlias<IClientInfoProvider, ClientInfoStorage>()
            .TryAddAlias<IClientInfoManager, ClientInfoStorage>();
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
        services.TryAddKeyedSingleton<IBinarySerializer, JsonBinarySerializer>(nameof(JsonBinarySerializer));
        services.TryAddKeyedSingleton<IBinarySerializer, ProtobufSerializer>(nameof(ProtobufSerializer));
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
        services.TryAddSingleton<IIssuerProvider>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<OidcOptions>>().Value;
            return options.Issuer != null
                ? sp.CreateService<PreconfiguredIssuerProvider>()
                : sp.CreateService<RequestBasedIssuerProvider>();
        });
        return services;
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
        services.TryAddEnumerable(ServiceDescriptor.Scoped<ILogoutNotifier, BackChannelLogoutNotifier>());
        services.TryAddSingleton<ILogoutTokenService, LogoutTokenService>();
        // The back-channel logout URI is a client-supplied URL, so POSTing logout tokens to it must
        // run through the SSRF-validating handler and carry a bounded timeout, like every other
        // server-initiated outbound request in this library.
        return services
            .AddSsrfHttpClient<ILogoutTokenSender, BackChannelLogoutTokenSender>((serviceProvider, client) =>
            {
                client.Timeout = serviceProvider.GetRequiredService<IOptions<SecureHttpFetchOptions>>()
                    .Value.RequestTimeout;
            })
            .Services;
    }

    /// <summary>
    /// Adds the necessary services for front-channel logout functionality to the specified <see cref="IServiceCollection"/>.
    /// Front-channel logout is typically used for web-based applications where the logout request is sent directly from
    /// the user's browser to the identity provider and other logged-in services.
    /// </summary>
    public static IServiceCollection AddFrontChannelLogout(this IServiceCollection services)
    {
        services.TryAddSingleton<IFrontChannelLogoutService, FrontChannelLogoutService>();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<ILogoutNotifier, FrontChannelLogoutNotifier>());
        return services;
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
        services.TryAddSingleton<IGrantIdGenerator, GrantIdGenerator>();
        services.TryAddSingleton<ISessionIdGenerator, SessionIdGenerator>();
        return services;
    }

    /// <summary>
    /// Adds services related to session management and decorates the authorization request processor within
    /// the specified <see cref="IServiceCollection"/>.
    /// </summary>
    public static IServiceCollection AddSessionManagement(this IServiceCollection services)
    {
        services.TryAddScoped<ISessionManagementService, SessionManagementService>();
        return services.Decorate<IAuthorizationRequestProcessor, AuthorizationRequestProcessorDecorator>();
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
        services.TryAddSingleton<IRefreshTokenService, RefreshTokenService>();
        return services;
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
        services.TryAddSingleton<IAccessTokenService, AccessTokenService>();
        return services;
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
        services.TryAddScoped<IIdentityTokenService, IdentityTokenService>();
        return services;
    }

    /// <summary>
    /// Registers JWT formatting and validation services for authentication within the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the JWT authentication services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further service registrations.</returns>
    public static IServiceCollection AddAuthServiceJwt(this IServiceCollection services)
    {
        services.TryAddSingleton<IAuthServiceKeysProvider, OidcOptionsKeysProvider>();

        // The write-role counterpart to the reader above. The default is the read-only static
        // configuration that fails loud if asked to persist a generated key; a persistent store (shipped
        // with key generation and rotation) replaces it host-first via TryAdd. It is segregated from the
        // reader (ISP), so read-only consumers never depend on persistence.
        services.TryAddSingleton<IAuthServiceKeysStore, ReadOnlyAuthServiceKeysStore>();

        services.TryAddSingleton<IAuthServiceJwtFormatter, AuthServiceJwtFormatter>();
        services.TryAddSingleton<IAuthServiceJwtValidator, AuthServiceJwtValidator>();
        return services;
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
        services.TryAddSingleton<IClientJwtValidator, ClientJwtValidator>();
        services.TryAddSingleton<IClientJwtFormatter, ClientJwtFormatter>();
        services.TryAddSingleton<IResponseJwtBuilder, ResponseJwtBuilder>();
        return services;
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
        services.TryAddSingleton<ITokenRegistry, TokenRegistry>();
        return services
            .Decorate<IJsonWebTokenValidator, TokenStatusValidatorDecorator>();
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
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, LicenseLoadingService>());
        services.TryAddSingleton<ILicenseJwtProvider, OptionsLicenseJwtProvider>();
        return services;
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
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, LicenseLoadingService>());
        // Intentional replacement: AddLicense(jwt) is an explicit host opt-in that must override
        // any ILicenseJwtProvider previously registered by AddLicenseFromOptions.
        services.Replace(ServiceDescriptor.Singleton<ILicenseJwtProvider>(
            sp => sp.CreateService<StaticLicenseJwtProvider>(Dependency.Override(licenseJwt))));
        return services;
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
        services.TryAddSingleton<IAuthorizationValueReuseDetector, AuthorizationValueReuseDetector>();
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
        services.TryAddSingleton<IResourceKeysProvider, ResourceKeysProvider>();
        return services;
    }

    /// <summary>
    /// Registers pairwise subject identifier settings, enabling reversible per-sector subject conversion for clients
    /// with SubjectType=pairwise. The salt and hash algorithm key a deterministic authenticated-encryption seal that
    /// produces stable, per-sector pseudonyms the server can open back to the real subject, per OpenID Connect Core
    /// Section 8.1.
    /// </summary>
    /// <param name="services">The service collection to register settings into.</param>
    /// <param name="settings">The pairwise subject settings containing the seal key (salt) and hash algorithm.</param>
    /// <exception cref="ArgumentException">The salt is missing, not valid base64, or decodes to fewer than
    /// <see cref="MinPairwiseSaltBytes"/> bytes. Validated here so a misconfigured seal key fails at startup rather
    /// than at the first token issuance or, worse, silently under a weak key.</exception>
    public static IServiceCollection AddPairwiseSubjectIdentifiers(
        this IServiceCollection services,
        PairwiseSubjectSettings settings)
    {
        ValidatePairwiseSalt(settings.Salt);
        services.TryAddSingleton(settings);
        return services;
    }

    /// <summary>
    /// The minimum decoded length of the pairwise salt. It is the sole key material of the pairwise seal, so it
    /// carries 256 bits of secret entropy - anything shorter weakens every pairwise identifier the server issues.
    /// </summary>
    private const int MinPairwiseSaltBytes = 32;

    private static void ValidatePairwiseSalt(string salt)
    {
        if (string.IsNullOrWhiteSpace(salt))
            throw new ArgumentException(
                "The pairwise salt is required: it is the key material of the pairwise subject seal.",
                nameof(salt));

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(salt);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "The pairwise salt must be a base64-encoded value.", nameof(salt), exception);
        }

        if (decoded.Length < MinPairwiseSaltBytes)
            throw new ArgumentException(
                $"The pairwise salt must decode to at least {MinPairwiseSaltBytes} bytes (256 bits) to key the " +
                $"pairwise subject seal securely, but it decoded to {decoded.Length} bytes.",
                nameof(salt));
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
    /// Opts the server into Client-Initiated Backchannel Authentication (CIBA). This single call registers the
    /// CIBA feature services, the CIBA grant handler, the backchannel endpoint services and re-enables the
    /// <see cref="OidcEndpoints.BackChannelAuthentication"/> flag, which is off in the default
    /// <see cref="OidcOptions.EnabledEndpoints"/>. A server that never calls this method exposes no backchannel
    /// endpoint and runs no CIBA grant.
    /// </summary>
    /// <remarks>
    /// Call this <b>before</b> <c>AddOidcCore</c>/<c>AddOidcServices</c>: the CIBA grant handler must be
    /// registered before <c>AddAuthorizationGrants()</c> composes the grant handlers at the end of
    /// <c>AddOidcCore</c>, otherwise it is registered beside the composite and the token endpoint resolves the
    /// wrong single <c>IAuthorizationGrantHandler</c>.
    /// </remarks>
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
            // Registered whatever the long-polling setting says. A factory that answers null publishes a
            // false non-null through the container: a consumer resolving it normally receives the null it
            // was promised was absent, an enumeration yields a null element, and GetRequiredService reports
            // the service as unregistered while a descriptor for it plainly exists. Constructing it when it
            // will not be used costs one object; the alternative costs a diagnosis.
            var logger = sp.GetRequiredService<ILogger<InMemoryLongPollingService>>();
            return new InMemoryLongPollingService(logger);
        });

        // Register HTTP client for backchannel notifications (ping and push modes) with configurable handler lifetime
        // Use configuration callback to get handler lifetime from OidcOptions
        services.AddOptions<HttpClientFactoryOptions>(nameof(HttpNotificationDeliveryService))
            .Configure<IOptions<OidcOptions>>((httpOptions, oidcOptions) =>
            {
                httpOptions.HandlerLifetime = oidcOptions.Value.BackChannelAuthentication.NotificationHttpClientHandlerLifetime;
            });

        // The notification endpoint is a client-supplied URL, so server-initiated POSTs to it must
        // run through the SSRF-validating handler (blocks internal hosts, private IPs, DNS rebinding)
        // and carry a bounded timeout, exactly like every other outbound fetch in this library.
        services.AddSsrfHttpClient(nameof(HttpNotificationDeliveryService), (serviceProvider, client) =>
        {
            client.Timeout = serviceProvider.GetRequiredService<IOptions<OidcOptions>>()
                .Value.BackChannelAuthentication.NotificationHttpClientTimeout;
        });

        // Register CIBA grant handler (dual: IAuthorizationGrantHandler + IGrantTypeInformer).
        services.AddAuthorizationGrant<BackChannelAuthenticationGrantHandler>();

        // Single opt-in: registering the feature also brings in the backchannel endpoint services and turns the
        // endpoint on. EnabledEndpoints defaults to OidcEndpoints.Base (CIBA off), so a server that never calls this
        // method neither registers the CIBA types nor advertises/validates the endpoint.
        services.AddBackChannelAuthenticationEndpoint();
        services.PostConfigure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.BackChannelAuthentication);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.BackChannelAuthentication);

        return services;
    }

    /// <summary>
    /// Opts the server into the Device Authorization Grant (RFC 8628). This single call registers the device
    /// feature services, the device endpoint (handler, validators, options validator) and re-enables the
    /// <see cref="OidcEndpoints.DeviceAuthorization"/> flag, which is off in the default
    /// <see cref="OidcOptions.EnabledEndpoints"/>. A server that never calls this method exposes no device
    /// endpoint and runs no device options validation.
    /// </summary>
    /// <remarks>
    /// Call this <b>before</b> <c>AddOidcCore</c>/<c>AddOidcServices</c>: the device-code grant handler must be
    /// registered before <c>AddAuthorizationGrants()</c> composes the grant handlers at the end of
    /// <c>AddOidcCore</c>, otherwise it is registered beside the composite and the token endpoint resolves the
    /// wrong single <c>IAuthorizationGrantHandler</c>.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddDeviceAuthorization(this IServiceCollection services)
    {
        services.TryAddSingleton<IDeviceCodeGenerator, DeviceCodeGenerator>();
        services.TryAddSingleton<IUserCodeGenerator, UserCodeGenerator>();
        services.TryAddSingleton<IUserCodeNormalizer, UserCodeNormalizer>();
        services.TryAddSingleton<IDeviceAuthorizationStorage, DeviceAuthorizationStorage>();
        services.TryAddSingleton<IUserCodeRateLimiter, UserCodeRateLimiter>();
        services.TryAddSingleton<IUserCodeVerificationService, UserCodeVerificationService>();

        // Register Device Authorization grant handler (dual: IAuthorizationGrantHandler + IGrantTypeInformer).
        services.AddAuthorizationGrant<DeviceCodeGrantHandler>();

        // Single opt-in: registering the feature also brings in the endpoint services (handler, validators,
        // the DeviceAuthorization options validator) and turns the endpoint on. EnabledEndpoints defaults to
        // OidcEndpoints.Base, which excludes DeviceAuthorization, so a server that never calls this method
        // neither registers the device types nor advertises/validates the endpoint.
        services.AddDeviceAuthorizationEndpoint();
        services.PostConfigure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.DeviceAuthorization);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.DeviceAuthorization);

        return services;
    }

    /// <summary>
    /// Opts the server into the OpenID Connect Session Management check-session endpoint. This single call
    /// registers the check-session handler and re-enables the <see cref="OidcEndpoints.CheckSession"/> flag,
    /// which is off in the default <see cref="OidcOptions.EnabledEndpoints"/>. Many SPAs do not use the
    /// session-management iframe, so it is opt-in: a server that never calls this method exposes no check-session
    /// endpoint and does not advertise it in discovery.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddCheckSession(this IServiceCollection services)
    {
        services.AddCheckSessionEndpoint();
        services.PostConfigure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.CheckSession);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.CheckSession);
        return services;
    }

    /// <summary>
    /// Opts the server into the OAuth 2.0 Token Revocation endpoint (RFC 7009). This single call registers the
    /// revocation handler, validator and processor and re-enables the <see cref="OidcEndpoints.Revocation"/>
    /// flag, which is off in the default <see cref="OidcOptions.EnabledEndpoints"/>. This governs only the public
    /// <c>/revoke</c> endpoint; the internal token-revocation machinery that refresh-token rotation, logout and
    /// initial-access-token invalidation depend on is always registered and is unaffected. A server that never
    /// calls this method exposes no revocation endpoint and does not advertise it in discovery.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddRevocation(this IServiceCollection services)
    {
        services.AddRevocationEndpoint();
        services.PostConfigure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.Revocation);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.Revocation);
        return services;
    }

    /// <summary>
    /// Opts the server into the OAuth 2.0 Token Introspection endpoint (RFC 7662). This single call registers the
    /// introspection handler, validator and processor and re-enables the <see cref="OidcEndpoints.Introspection"/>
    /// flag, which is off in the default <see cref="OidcOptions.EnabledEndpoints"/>. Introspection is chiefly
    /// needed by resource servers validating opaque tokens; a server issuing self-contained JWTs often does not
    /// need it, so it is opt-in. A server that never calls this method exposes no introspection endpoint and does
    /// not advertise it in discovery.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddIntrospection(this IServiceCollection services)
    {
        services.AddIntrospectionEndpoint();
        services.PostConfigure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.Introspection);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.Introspection);
        return services;
    }

    /// <summary>
    /// Opts the server into Dynamic Client Registration (RFC 7591 / RFC 7592). This single call registers the
    /// registration, read, update and remove handlers and their validators, and re-enables the
    /// <see cref="OidcEndpoints.RegisterClient"/> flag, which is off in the default
    /// <see cref="OidcOptions.EnabledEndpoints"/>. Open registration widens the attack surface, so it is opt-in:
    /// a server that never calls this method exposes no registration endpoint and does not advertise it in
    /// discovery. New-client defaults are taken from <see cref="OidcOptions.NewClientOptions"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddDynamicClientRegistration(this IServiceCollection services)
    {
        services.AddDynamicClientEndpoints(sp => sp.GetRequiredService<IOptions<OidcOptions>>().Value.NewClientOptions);
        services.PostConfigure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.RegisterClient);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.RegisterClient);
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

        // The framework resolves every registered validator, so this joins the set rather than replacing
        // whatever a host registered for the same options.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<SecureHttpFetchOptions>, SecureHttpFetchOptionsValidator>());

        services.TryAddSingleton<ISecureUriValidator, SecureUriValidator>();
        services.TryAddTransient<SsrfValidatingHttpMessageHandler>();

        services.AddSsrfHttpClient<ISecureHttpFetcher, SecureHttpFetcher>((serviceProvider, client) =>
        {
            var options = serviceProvider.GetRequiredService<IOptions<SecureHttpFetchOptions>>().Value;
            client.Timeout = options.RequestTimeout;
        });

        // One cached fetcher per consumer, each keyed by who asks and carrying its own lifetime. Caching used
        // to hang off a single service key that only the JWT bearer grant read, so client, software-statement
        // and resource key sets were fetched over the network on every use. Giving each consumer its own
        // instance keeps the lifetime a property of the caller without putting it into the transport contract:
        // how stale a document may be depends on what it is used for, and a resource key set backing every
        // token issued is not the same case as a client key set read on the occasional request object.
        services.AddCachedSecureHttpFetcher(
            KeySetOwners.Client,
            fetch => fetch.ClientKeysCacheDuration);

        services.AddCachedSecureHttpFetcher(
            KeySetOwners.Resource,
            fetch => fetch.ResourceKeysCacheDuration);

        services.AddCachedSecureHttpFetcher(
            KeySetOwners.SoftwareStatementIssuer,
            fetch => fetch.SoftwareStatementKeysCacheDuration);

        // The JWT bearer grant keeps its own long-standing setting, which lives with the rest of that
        // feature's options rather than here.
        services.DecorateKeyed<ISecureHttpFetcher, CachingSecureHttpFetcherDecorator>(
            KeySetOwners.Issuer,
            Dependency.Override(serviceProvider => serviceProvider
                .GetRequiredService<IOptionsMonitor<OidcOptions>>()
                .CurrentValue.JwtBearer.JwksCacheDuration));

        return services;
    }

    /// <summary>
    /// Registers a caching <see cref="ISecureHttpFetcher"/> for one consumer, under its own service key and
    /// with its own cache lifetime.
    /// </summary>
    /// <param name="services">The service collection to add the registration to.</param>
    /// <param name="consumer">The consumer's key, from <see cref="KeySetOwners"/>.</param>
    /// <param name="duration">Reads the consumer's lifetime out of the options. Resolved through a factory
    /// rather than captured here, so a host configuring options after this call is still honoured.</param>
    private static void AddCachedSecureHttpFetcher(
        this IServiceCollection services,
        string consumer,
        Func<SecureHttpFetchOptions, TimeSpan> duration)
        => services.DecorateKeyed<ISecureHttpFetcher, CachingSecureHttpFetcherDecorator>(
            consumer,
            Dependency.Override(serviceProvider => duration(
                serviceProvider.GetRequiredService<IOptionsMonitor<SecureHttpFetchOptions>>().CurrentValue)));

    /// <summary>
    /// Registers the generic stateless-nonce service. The default
    /// <see cref="RollingHmacNonceService"/> implementation is shared across
    /// any feature that needs server-issued, time-bounded opaque tokens
    /// (DPoP-Nonce per RFC 9449 §8 / §9 is the current consumer; future
    /// candidates include state-parameter validation and challenge-response
    /// patterns). Idempotent via <c>TryAdd</c> so feature-level
    /// <c>Add*</c> methods can declare the dependency without contention.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection AddNonces(this IServiceCollection services)
    {
        services.TryAddSingleton<INonceService, RollingHmacNonceService>();
        return services;
    }

    /// <summary>
    /// Registers the OAuth 2.0 DPoP (RFC 9449) infrastructure: the proof
    /// validator, the JWT replay cache it depends on (via defensive
    /// <c>TryAdd</c> so DPoP-only deployments do not need to enable JWT Bearer
    /// just to get the cache), and the shared nonce-service via
    /// <see cref="AddNonces"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection AddDPoP(this IServiceCollection services)
    {
        services.TryAddSingleton<IProofValidator, ProofValidator>();
        services.AddReplayPrevention();
        return services.AddNonces();
    }
}
