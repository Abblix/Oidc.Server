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

namespace Abblix.Oidc.Client.Common;

/// <summary>
/// The scope values OpenID Connect Core 1.0 section 5.4 defines, as they appear on the wire.
/// </summary>
/// <remarks>
/// Shared across features rather than owned by one: the same values are asked for in an authorization
/// request, in a CIBA request and at the token endpoint, and a client that spelled one of them differently in
/// one place would be asking for a scope no provider grants.
///
/// Named the same as on the provider side of this repository, deliberately. The two sets of constants are
/// separate because the client must not depend on the server package, so keeping the names identical by hand
/// is what stops a reader from looking for a difference that is not there.
/// </remarks>
public static class Scopes
{
    /// <summary>
    /// Asks for authentication rather than mere authorization. Required of every OpenID Connect request, and
    /// of every CIBA request by that specification's section 7.1.
    /// </summary>
    public const string OpenId = "openid";

    /// <summary>Asks for the end-user's default profile claims.</summary>
    public const string Profile = "profile";

    /// <summary>Asks for the end-user's email address and whether it is verified.</summary>
    public const string Email = "email";

    /// <summary>Asks for the end-user's phone number and whether it is verified.</summary>
    public const string Phone = "phone";

    /// <summary>Asks for the end-user's postal address.</summary>
    public const string Address = "address";

    /// <summary>Asks for a refresh token, so the session can be continued without the user.</summary>
    public const string OfflineAccess = "offline_access";
}
