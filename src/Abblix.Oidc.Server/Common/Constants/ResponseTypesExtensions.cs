// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Extension methods that classify an OAuth 2.0 <c>response_type</c> combination - the array of its
/// space-separated parts (<c>code</c>, <c>token</c>, <c>id_token</c>). They centralise the shared
/// response-type predicates so the same rule is applied wherever a request's flow is derived from its
/// response types.
/// </summary>
public static class ResponseTypesExtensions
{
    /// <summary>
    /// Determines whether a <c>response_type</c> combination returns a token directly from the
    /// authorization endpoint - that is, whether it contains the <c>token</c> or <c>id_token</c> part
    /// and is therefore an implicit or hybrid flow rather than the plain authorization code flow. The
    /// single definition of "token-bearing response type" used by both the flow-type validator and
    /// the security-profile consistency check.
    /// </summary>
    internal static bool ReturnsTokenFromAuthorization(this string[]? responseType)
        => responseType.HasFlag(ResponseTypes.Token) || responseType.HasFlag(ResponseTypes.IdToken);
}