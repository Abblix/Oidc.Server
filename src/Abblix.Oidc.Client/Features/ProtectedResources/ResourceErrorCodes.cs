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


namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <summary>
/// The error codes a resource server returns in a Bearer challenge (RFC 6750 section 3.1).
/// </summary>
/// <remarks>
/// A different set from the token endpoint's (RFC 6749 section 5.2) and from the authorization endpoint's,
/// answered by a different party about a different question, which is why this client carries three classes
/// of this name rather than one.
/// </remarks>
public static class ResourceErrorCodes
{
    /// <summary>
    /// The request was malformed. RFC 6750 section 3.1 pairs it with 400.
    /// </summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>
    /// The token was rejected: expired, revoked, malformed, or otherwise not accepted. Paired with 401.
    /// </summary>
    public const string InvalidToken = "invalid_token";

    /// <summary>
    /// The token is valid but does not carry enough scope for what was asked. Paired with 403.
    /// </summary>
    /// <remarks>
    /// The one that must not be mistaken for <see cref="InvalidToken"/>: signing the user in again with the
    /// same scopes produces the same refusal, forever.
    /// </remarks>
    public const string InsufficientScope = "insufficient_scope";
}
