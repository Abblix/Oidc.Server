// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The link of the JWT validation chain that checks the <c>iss</c> claim.
/// </summary>
internal static class JwtIssuerValidator
{
    /// <summary>
    /// Validates the issuer claim according to validation parameters.
    /// </summary>
    public static async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
        JsonWebToken token, ValidationParameters parameters)
    {
        var issuer = token.Payload.Issuer;

        if (issuer is null)
        {
            return parameters.Options.HasFlag(ValidationOptions.RequireIssuer)
                ? new JwtValidationError(JwtError.InvalidToken, "Missing issuer in JWT payload")
                : token;
        }

        // Presence and validity are separate questions gated by separate flags, the same split
        // ValidateLifetime and RequireExpirationTime already use: RequireIssuer says iss has to be there,
        // ValidateIssuer says the one that is there must satisfy the caller's delegate. Reading either flag
        // as "run the delegate" made the documented use of RequireIssuer on its own throw instead of
        // validating.
        if (!parameters.Options.HasFlag(ValidationOptions.ValidateIssuer))
            return token;

        // The same category of mismatch as a missing key resolver, and answered the same way: the caller
        // asked for the issuer to be checked and wired nothing to check it with, which is a misconfiguration
        // this token cannot survive - but it is the token that fails, not the process. An
        // InvalidOperationException here would reach the host as a 500 on a request that deserves a refusal.
        if (parameters.ValidateIssuer is not { } validateIssuer)
        {
            return new JwtValidationError(
                JwtError.InvalidToken,
                $"No issuer validator configured: {nameof(ValidationOptions.ValidateIssuer)} is set but "
                + $"{nameof(ValidationParameters.ValidateIssuer)} was not supplied.");
        }

        return await validateIssuer(issuer)
            ? token
            : new JwtValidationError(JwtError.InvalidToken, $"Invalid issuer: {issuer}");
    }
}
