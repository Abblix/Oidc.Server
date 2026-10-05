// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization;
using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the Device Authorization Grant (RFC 8628) endpoint and its validation pipeline.
/// </summary>
public static class DeviceAuthorizationServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Device Authorization Grant (RFC 8628) endpoint services - handler, request and context
    /// validators, and the <c>DeviceAuthorizationOptionsValidator</c>. Invoked by the public
    /// <c>AddDeviceAuthorization()</c> opt-in method, not by the unconditional endpoint wiring: device
    /// authorization is a single opt-in feature, so its validator only runs when a server opts in.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddDeviceAuthorizationEndpoint(this IServiceCollection services)
    {
        services.AddDeviceAuthorizationContextValidators();
        services.TryAddScoped<IDeviceAuthorizationHandler, DeviceAuthorizationHandler>();
        services.AddEndpointSpan<IDeviceAuthorizationHandler, TracedDeviceAuthorizationHandler>();
        services.TryAddScoped<IDeviceAuthorizationRequestValidator, DeviceAuthorizationRequestValidator>();
        services.TryAddScoped<IDeviceAuthorizationRequestProcessor, DeviceAuthorizationRequestProcessor>();

        // Fail loud at startup when the device endpoint is enabled but its settings are absent, instead of letting the
        // gap surface as an unhandled 500 on the first request. TryAddEnumerable because the options framework
        // resolves every registered IValidateOptions.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, DeviceAuthorizationOptionsValidator>());

        return services;
    }

    /// <summary>
    /// Configures and registers a composite of device authorization context validators into the
    /// service collection. Validators run in sequence to verify the client, the requested resources,
    /// and the requested scopes before a device authorization request (RFC 8628) is accepted.
    /// </summary>
    /// <param name="services">The service collection to which the device authorization context validators will be added.</param>
    /// <returns>The modified service collection with the registered device authorization context validators.</returns>
    public static IServiceCollection AddDeviceAuthorizationContextValidators(this IServiceCollection services)
    {
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorization.Validation.ClientValidator>(),
            // The resources go first: a scope only a resource declares is judged against the resources requested
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorization.Validation.ResourceValidator>(),
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorization.Validation.ScopeValidator>(),
            // RFC 9396 section 3 authorization_details on device authorization requests.
            ServiceDescriptor.Singleton<IDeviceAuthorizationContextValidator, DeviceAuthorizationDetailsValidator>(),
        ]);
        return services.Compose<IDeviceAuthorizationContextValidator, DeviceAuthorizationValidatorComposite>();
    }
}
