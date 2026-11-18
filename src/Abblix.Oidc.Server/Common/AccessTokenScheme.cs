// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// The authentication scheme a request presented its access token with, which decides the challenge that carries the
/// error when a refusal advertises more than one (RFC 9449 section 7.2).
/// </summary>
public enum AccessTokenScheme
{
    /// <summary>
    /// The Bearer scheme of RFC 6750: the <c>Authorization: Bearer</c> header, or the <c>access_token</c> parameter
    /// in the body or the query, both among the "three methods of sending bearer access tokens" of section 2.
    /// </summary>
    Bearer,

    /// <summary>The DPoP scheme of RFC 9449 section 7.1: the <c>Authorization: DPoP</c> header.</summary>
    DPoP,
}
