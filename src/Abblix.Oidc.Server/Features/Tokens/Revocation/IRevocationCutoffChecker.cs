// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Decides whether a subject- or session-level revocation cutoff refuses a token.
/// </summary>
/// <remarks>
/// Separate from the validator that consults it because the two answer different questions from different
/// stores. The validator asks what is recorded about this one token; a cutoff is a fact about the principal,
/// and answering it means naming the issuer, opening a pairwise pseudonym and allowing for the clock of
/// whichever instance recorded the revocation. Keeping that here also lets it be exercised on its own,
/// without a token registry and an inner validator standing in the way of every case.
/// </remarks>
public interface IRevocationCutoffChecker
{
    /// <summary>
    /// The refusal a cutoff calls for on this token, or <c>null</c> when no cutoff reaches it.
    /// </summary>
    /// <param name="payload">The payload of a token that has already passed signature and lifetime checks.</param>
    /// <returns>A validation error when the token is refused, otherwise <c>null</c>.</returns>
    Task<JwtValidationError?> CheckAsync(JsonWebTokenPayload payload);
}
