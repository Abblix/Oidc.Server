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

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// Provides extension methods for <see cref="IServiceCollection"/> to register JwT-related services within the application.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers services for creating and validating JSON Web Tokens (JWTs) within the application.
    /// </summary>
    /// <remarks>
    /// This method adds services for JWT handling, enabling the application to generate and validate JWTs efficiently.
    /// JWTs are an essential part of modern web application security, used for representing claims securely between
    /// two parties.
    ///
    /// By registering these services, the application can:
    /// - Create JWTs with <see cref="IJsonWebTokenCreator"/>, allowing for the generation of tokens that can securely
    /// transmit information between parties.
    /// - Validate JWTs with <see cref="IJsonWebTokenValidator"/>, ensuring that incoming tokens are valid and
    /// have not been tampered with.
    ///
    /// This setup is crucial for implementing authentication and authorization mechanisms that rely on JWTs,
    /// such as OAuth 2.0 and OpenID Connect.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure with JWT services.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>, enabling further chaining of service registrations.</returns>
    public static IServiceCollection AddJsonWebTokens(this IServiceCollection services)
    {
        return services
            .AddSingleton<IJsonWebTokenCreator, JsonWebTokenCreator>()
            .AddSingleton<IJsonWebTokenValidator, JsonWebTokenValidator>();
    }
}
