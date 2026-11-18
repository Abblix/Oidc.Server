// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The link of the JWT validation chain that checks the <c>aud</c> claim.
/// </summary>
internal static class JwtAudienceValidator
{
    /// <summary>
    /// Validates the audience claim according to validation parameters.
    /// </summary>
    public static async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
        JsonWebToken token, ValidationParameters parameters)
    {
        var audiencesList = token.Payload.Audiences.ToList();

        if (audiencesList.Count == 0)
        {
            return parameters.Options.HasFlag(ValidationOptions.RequireAudience)
                ? new JwtValidationError(JwtError.InvalidToken, "Missing audience in JWT payload")
                : token;
        }

        // The same split as in JwtIssuerValidator: requiring aud to be present says nothing about who may check
        // it.
        if (!parameters.Options.HasFlag(ValidationOptions.ValidateAudience))
            return token;

        if (parameters.ValidateAudience is not { } validateAudience)
        {
            return new JwtValidationError(
                JwtError.InvalidToken,
                $"No audience validator configured: {nameof(ValidationOptions.ValidateAudience)} is set but "
                + $"{nameof(ValidationParameters.ValidateAudience)} was not supplied.");
        }

        return await validateAudience(audiencesList)
            ? token
            : new JwtValidationError(JwtError.InvalidToken, $"Invalid audience: {string.Join(", ", audiencesList)}");
    }
}
