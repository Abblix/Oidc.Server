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

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Records which opt-in OIDC endpoints have had their feature services registered via the corresponding
/// <c>AddX()</c> call. It is order-independent: every <c>AddX()</c> contributes its flag through
/// <c>Configure</c>, so the accumulated set is available regardless of whether the opt-in ran before or after
/// <c>AddOidcCore</c>. <see cref="EnabledEndpointsRegistrationValidator"/> reads it to fail fast when
/// <see cref="OidcOptions.EnabledEndpoints"/> advertises an opt-in endpoint whose handler was never registered.
/// </summary>
internal sealed class EndpointRegistrationMarker
{
    /// <summary>The opt-in endpoints whose feature services are actually registered.</summary>
    public OidcEndpoints Registered { get; set; }
}

/// <summary>
/// Fails fast when <see cref="OidcOptions.EnabledEndpoints"/> enables an opt-in endpoint (CheckSession,
/// Revocation, Introspection, dynamic client registration, CIBA or device authorization) whose feature services
/// were not registered by the matching <c>AddX()</c> opt-in. The flag only advertises and routes the endpoint;
/// its handler is registered solely by the opt-in, so setting <c>All</c> (or the flag) without the opt-in would
/// advertise an endpoint that fails on every request. This turns that silent per-request failure into a clear
/// startup error, honouring RFC 8414 §2 / OpenID Connect Discovery §3 — do not advertise capabilities the server
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
            "Call the corresponding Add… method (AddCheckSession, AddRevocation, AddIntrospection, " +
            "AddDynamicClientRegistration, AddBackChannelAuthentication, AddDeviceAuthorization) for each advertised " +
            "endpoint, or remove it from EnabledEndpoints.");
    }
}
