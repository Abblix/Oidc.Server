// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Turns an <c>id_token_hint</c> parameter into the ID token it claims to be, or into the reason it is not
/// one.
/// </summary>
/// <remarks>
/// Two endpoints take a hint - authorization (OpenID Connect Core 1.0 Section 3.1.2.1) and end session
/// (RP-Initiated Logout 1.0 Section 2) - and what makes a hint believable is the same for both, while what
/// each does with the result is not. Shared here rather than written twice, because the two copies had
/// already begun to differ: one required the expiration time through the validator and the other tested for
/// it by hand.
/// </remarks>
public interface IIdTokenHintParser
{
    /// <summary>
    /// Validates a hint and returns the ID token, or a description of why it is not acceptable.
    /// </summary>
    /// <param name="idTokenHint">The raw parameter value.</param>
    /// <returns>
    /// The validated ID token, or a human-readable reason the caller wraps in its own error shape - the two
    /// endpoints report failures as different types.
    /// </returns>
    Task<Result<JsonWebToken, string>> ParseAsync(string idTokenHint);
}
