// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Fails fast when <see cref="OidcOptions.EnabledEndpoints"/> enables an opt-in endpoint (CheckSession,
/// Revocation, Introspection, dynamic client registration, CIBA or device authorization) whose feature services
/// were not registered by the matching <c>AddX()</c> opt-in. The flag only advertises and routes the endpoint;
/// its handler is registered solely by the opt-in, so setting <c>All</c> (or the flag) without the opt-in would
/// advertise an endpoint that fails on every request. This turns that silent per-request failure into a clear
/// startup error, honouring RFC 8414 §2 / OpenID Connect Discovery §3 - do not advertise capabilities the server
/// does not actually serve.
/// </summary>
internal sealed class EnabledEndpointsRegistrationValidator(IOptions<EndpointRegistrationMarker> marker)
    : IValidateOptions<OidcOptions>
{
    // Endpoints off in the default Base set, each turned on (and its handler registered) only by its AddX() call.
    private const OidcEndpoints OptInEndpoints =
        OidcEndpoints.CheckSession | OidcEndpoints.Revocation | OidcEndpoints.Introspection |
        OidcEndpoints.RegisterClient | OidcEndpoints.BackChannelAuthentication | OidcEndpoints.DeviceAuthorization;

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var advertisedButUnregistered = options.EnabledEndpoints & OptInEndpoints & ~marker.Value.Registered;
        if (advertisedButUnregistered == default)
            return ValidateOptionsResult.Success;

        return ValidateOptionsResult.Fail(
            $"EnabledEndpoints advertises {advertisedButUnregistered}, but the matching opt-in feature method was " +
            "not called, so the endpoint's handler is not registered and every request to it would fail at runtime. " +
            "Call the corresponding Add... method (AddCheckSession, AddRevocation, AddIntrospection, " +
            "AddDynamicClientRegistration, AddBackChannelAuthentication, AddDeviceAuthorization) for each advertised " +
            "endpoint, or remove it from EnabledEndpoints.");
    }
}
