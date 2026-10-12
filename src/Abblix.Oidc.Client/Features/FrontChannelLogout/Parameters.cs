// Abblix OIDC Client Library
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


namespace Abblix.Oidc.Client.Features.FrontChannelLogout;

/// <summary>
/// The query parameters a front-channel logout request may carry, named as on the wire.
/// </summary>
/// <remarks>
/// Both are defined by OpenID Connect Front-Channel Logout 1.0 section 2, which allows the provider to add
/// them and requires that neither travels without the other.
/// </remarks>
public static class Parameters
{
    /// <summary>
    /// The provider the request comes from.
    /// </summary>
    public const string Issuer = "iss";

    /// <summary>
    /// The session that has ended.
    /// </summary>
    public const string SessionId = "sid";
}
