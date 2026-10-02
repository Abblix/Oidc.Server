// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring the Device Authorization Grant.
/// </summary>
public static class DeviceAuthorizationServiceCollectionExtensions
{
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
}
