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

namespace Abblix.Oidc.Client.Features.UserInfo;

/// <summary>
/// The authentication schemes a token is presented under, as they appear on the wire.
/// </summary>
/// <remarks>
/// Named to match <c>Abblix.Oidc.Server.Common.Constants.TokenTypes</c>. The client cannot reference the
/// server package, so the constants are kept in step by hand - the same arrangement the wire constants for
/// requests and responses already use.
/// </remarks>
public static class TokenTypes
{
    /// <summary>
    /// A bearer token, presented as <c>Authorization: Bearer &lt;token&gt;</c> (RFC 6750 section 2.1).
    /// </summary>
    public const string Bearer = "Bearer";

    /// <summary>
    /// A token bound to a proof of possession, presented as <c>Authorization: DPoP &lt;token&gt;</c>
    /// (RFC 9449 section 7.1). Named here because a paid layer presents tokens this way; the base client
    /// issues no DPoP proofs.
    /// </summary>
    public const string DPoP = "DPoP";
}
