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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Extension methods that classify an OAuth 2.0 <c>response_type</c> combination — the array of its
/// space-separated parts (<c>code</c>, <c>token</c>, <c>id_token</c>). They centralise the shared
/// response-type predicates so the same rule is applied wherever a request's flow is derived from its
/// response types.
/// </summary>
public static class ResponseTypesExtensions
{
    /// <summary>
    /// Determines whether a <c>response_type</c> combination returns a token directly from the
    /// authorization endpoint — that is, whether it contains the <c>token</c> or <c>id_token</c> part
    /// and is therefore an implicit or hybrid flow rather than the plain authorization code flow. The
    /// single definition of "token-bearing response type" used by both the flow-type validator and
    /// the security-profile consistency check.
    /// </summary>
    internal static bool ReturnsTokenFromAuthorization(this string[]? responseType)
        => responseType.HasFlag(ResponseTypes.Token) || responseType.HasFlag(ResponseTypes.IdToken);
}