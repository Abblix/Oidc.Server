// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Stable endpoint names assigned to each mapped route via <c>WithName</c>.
/// </summary>
/// <remarks>
/// The discovery document advertises absolute URLs for the provider's endpoints. The MVC integration resolves those
/// URLs from controller/action descriptors; Minimal API resolves them from named endpoints through
/// <see cref="Microsoft.AspNetCore.Routing.LinkGenerator"/>, so each endpoint carries a name that stays stable across
/// route reconfiguration.
/// </remarks>
internal static class EndpointNames
{
    private const string Prefix = $"{nameof(Abblix)}.{nameof(Oidc)}.";

    public const string Authorize = Prefix + nameof(Authorize);
    public const string PushedAuthorizationRequest = Prefix + nameof(PushedAuthorizationRequest);
    public const string UserInfo = Prefix + nameof(UserInfo);
    public const string EndSession = Prefix + nameof(EndSession);
    public const string CheckSession = Prefix + nameof(CheckSession);
    public const string Token = Prefix + nameof(Token);
    public const string Revocation = Prefix + nameof(Revocation);
    public const string Introspection = Prefix + nameof(Introspection);
    public const string BackChannelAuthentication = Prefix + nameof(BackChannelAuthentication);
    public const string DeviceAuthorization = Prefix + nameof(DeviceAuthorization);
    public const string Register = Prefix + nameof(Register);
    public const string RegisterClient = Prefix + nameof(RegisterClient);
    public const string Configuration = Prefix + nameof(Configuration);
    public const string OAuthAuthorizationServer = Prefix + nameof(OAuthAuthorizationServer);
    public const string Keys = Prefix + nameof(Keys);
}
