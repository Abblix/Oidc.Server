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
