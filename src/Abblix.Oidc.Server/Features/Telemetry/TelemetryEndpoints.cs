// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The values of <see cref="TelemetryTags.Endpoint"/>, which also name the endpoint spans.
/// </summary>
public static class TelemetryEndpoints
{
    /// <summary>The authorization endpoint.</summary>
    public const string Authorize = "authorize";

    /// <summary>The pushed authorization request endpoint.</summary>
    public const string PushedAuthorization = "par";

    /// <summary>The token endpoint.</summary>
    public const string Token = "token";

    /// <summary>The userinfo endpoint.</summary>
    public const string UserInfo = "userinfo";

    /// <summary>The end session endpoint.</summary>
    public const string EndSession = "end_session";

    /// <summary>The check session iframe.</summary>
    public const string CheckSession = "check_session";

    /// <summary>The revocation endpoint.</summary>
    public const string Revocation = "revocation";

    /// <summary>The introspection endpoint.</summary>
    public const string Introspection = "introspection";

    /// <summary>The back-channel authentication endpoint.</summary>
    public const string BackChannelAuthentication = "backchannel_authentication";

    /// <summary>The device authorization endpoint.</summary>
    public const string DeviceAuthorization = "device_authorization";

    /// <summary>The client registration endpoint.</summary>
    public const string RegisterClient = "register";

    /// <summary>Reading a registered client's configuration.</summary>
    public const string ReadClient = "read_client";

    /// <summary>Updating a registered client's configuration.</summary>
    public const string UpdateClient = "update_client";

    /// <summary>Removing a registered client.</summary>
    public const string RemoveClient = "remove_client";

    /// <summary>The discovery document.</summary>
    public const string Configuration = "configuration";
}
