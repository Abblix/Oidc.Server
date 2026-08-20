// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;

/// <summary>
/// Represents a response indicating that the token has been successfully revoked.
/// </summary>
/// <param name="TokenId">The unique identifier (jti) of the revoked token, if available.</param>
/// <param name="TokenTypeHint">The type hint of the token that was revoked (e.g., access_token, refresh_token).</param>
/// <param name="RevokedAt">The timestamp when the token was revoked.</param>
public record TokenRevoked(
    string? TokenId,
    string? TokenTypeHint,
    DateTimeOffset RevokedAt);
