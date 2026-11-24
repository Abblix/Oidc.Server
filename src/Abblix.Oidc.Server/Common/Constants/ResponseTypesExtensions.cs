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
    /// single definition of "token-bearing response type" the flow-type validator derives the flow and
    /// the error response mode from.
    /// </summary>
    internal static bool ReturnsTokenFromAuthorization(this string[]? responseType)
        => responseType.HasFlag(ResponseTypes.Token) || responseType.HasFlag(ResponseTypes.IdToken);

    /// <summary>
    /// Determines whether a <c>response_type</c> combination is <c>code</c> and nothing else, the one value FAPI 2.0
    /// Security Profile section 5.3.2.2 admits: "authorization servers shall require the value of response_type
    /// described in [RFC6749] to be code". The single definition used by both the flow-type validator and the
    /// security-profile consistency check.
    /// </summary>
    internal static bool IsCodeAlone(this string[]? responseType)
        => responseType is { Length: 1 } && responseType.HasFlag(ResponseTypes.Code);

    /// <summary>
    /// Determines whether a native app may use a <c>response_type</c> combination: only one carrying a code, which
    /// PKCE protects, and issuing no access token at the authorization endpoint. RFC 8252 section 8.2: "as the implicit
    /// flow cannot be protected by PKCE [RFC7636] (which is required in Section 8.1), the use of the Implicit Flow with
    /// native apps is NOT RECOMMENDED", and RFC 9700 section 2.1.2 has clients use a response type "that causes the
    /// authorization server to issue access tokens in the token response", which a hybrid one carrying
    /// <c>token</c> does not. The response type <c>none</c> issues nothing at all, so a native app may use it too. The
    /// single definition the check of the settings, dynamic registration and the authorization endpoint hold a native
    /// app to.
    /// </summary>
    internal static bool ServesNativeApps(this string[]? responseType)
        => (responseType.HasFlag(ResponseTypes.Code) && !responseType.HasFlag(ResponseTypes.Token)) ||
           responseType is [ResponseTypes.None];
}