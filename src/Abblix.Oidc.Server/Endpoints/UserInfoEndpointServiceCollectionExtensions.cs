// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Endpoints.UserInfo;
using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the UserInfo endpoint.
/// </summary>
public static class UserInfoEndpointServiceCollectionExtensions
{
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
        services.AddTelemetryDecorator<IUserInfoHandler, TracedUserInfoHandler>();
        services.TryAddScoped<IUserInfoRequestValidator, UserInfoRequestValidator>();
        services.TryAddScoped<IUserInfoRequestProcessor, UserInfoRequestProcessor>();
        services.TryAddSingleton<IDPoPUserInfoValidator, UserInfo.Validation.DPoPUserInfoValidator>();
        services.TryAddSingleton<IMtlsUserInfoValidator, UserInfo.Validation.MtlsUserInfoValidator>();
        return services;
    }
}
