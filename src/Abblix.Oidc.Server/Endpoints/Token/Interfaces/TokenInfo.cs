// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Identity of an issued token, recorded against an authorization grant so that the token can be
/// revoked by JTI if the grant is later invalidated (for example when an authorization code is reused).
/// </summary>
/// <param name="JwtId">The token's <c>jti</c> claim.</param>
/// <param name="ExpiresAt">When the token expires; used to expire the revocation record alongside the token itself.</param>
public record TokenInfo(string JwtId, DateTimeOffset ExpiresAt);
