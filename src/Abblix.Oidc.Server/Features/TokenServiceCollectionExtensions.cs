// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring
/// the tokens this server issues and their revocation.
/// </summary>
public static class TokenServiceCollectionExtensions
{
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
        // The whole revocation substrate, not only the decoration: a host calling this alone gets the
        // status registry a replay trips, the cutoff registry a suspension writes, and the surface it
        // writes through.
        services.TryAddSingleton<ITokenRegistry, TokenRegistry>();
        services.TryAddSingleton<IRevocationCutoffRegistry, RevocationCutoffRegistry>();
        services.TryAddSingleton<IRevocationCutoffChecker, RevocationCutoffChecker>();
        services.TryAddSingleton<ITokenRevoker, TokenRevoker>();
        services.TryAddSingleton<GrantRevocation>();
        services.TryAddSingleton(TimeProvider.System);
        return services
            .Decorate<IJsonWebTokenValidator, TokenStatusValidatorDecorator>();
    }
}
