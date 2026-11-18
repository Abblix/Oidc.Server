// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The last link of the JWT validation chain: checks the token's timestamps against this server's clock.
/// </summary>
/// <param name="timeProvider">The clock the timestamps are compared against.</param>
internal sealed class JwtLifetimeValidator(TimeProvider timeProvider)
{
    /// <summary>
    /// Validates the lifetime claims (nbf and exp) according to validation parameters.
    /// </summary>
    /// <remarks>
    /// Presence and value are two separate questions here, gated by two separate flags, the same
    /// way <see cref="ValidationOptions.RequireIssuer"/> and <see cref="ValidationOptions.ValidateIssuer"/>
    /// split them. The distinction is not academic: a token carrying neither <c>nbf</c> nor
    /// <c>exp</c> has no instant at which it is expired, so a pure lifetime comparison finds
    /// nothing wrong with it and lets it through forever. Whether that is correct depends
    /// entirely on the token type, which only the caller knows -
    /// <see cref="ValidationOptions.RequireExpirationTime"/> is how it says so.
    /// </remarks>
    public Result<JsonWebToken, JwtValidationError> Validate(
        JsonWebToken token, ValidationParameters parameters)
    {
        var requireExpiration = parameters.Options.HasFlag(ValidationOptions.RequireExpirationTime);
        var validateLifetime = parameters.Options.HasFlag(ValidationOptions.ValidateLifetime);

        // Neither flag set means the claims are not this caller's business, so they are not read
        // at all: a caller who opted out of time handling is not told the token's dates are wrong.
        if (!requireExpiration && !validateLifetime)
            return token;

        // A timestamp the payload cannot read is the token's fault, not this server's, so it is
        // refused rather than allowed to escape as an exception out of the request. The token itself
        // parsed, which is why this is an invalid claim and not a malformed token.
        if (!token.Payload.TryReadTimestamps(out var notBefore, out var expiresAt, out var issuedAt, out var whyUnreadable))
            return new JwtValidationError(JwtError.InvalidToken, whyUnreadable);

        if (requireExpiration && !expiresAt.HasValue)
            return new JwtValidationError(JwtError.InvalidToken, "Missing expiration time in JWT payload");

        if (!validateLifetime)
            return token;

        if (!notBefore.HasValue && !expiresAt.HasValue && !issuedAt.HasValue)
            return token;

        return CompareTimestamps(token, parameters, notBefore, expiresAt, issuedAt);
    }

    /// <summary>
    /// Compares the three timestamps a token may carry against this server's clock, in the order a
    /// sender needs to hear about them.
    /// </summary>
    /// <remarks>
    /// The order is a decision, not an accident. A token carrying both <c>nbf</c> and <c>iat</c>
    /// ahead of this clock is post-dated, and "not yet valid" is what its sender needs to hear;
    /// answering about <c>iat</c> there would change which reason a caller is given for a refusal
    /// that already existed.
    ///
    /// Only the future direction of <c>iat</c> is checked. An <c>iat</c> in the past says nothing on
    /// its own: how old a token may be is a question about the token's kind, which the caller
    /// answers with <c>exp</c> or with its own maximum age, and answering it here would refuse every
    /// long-lived token this validator also serves. An <c>iat</c> ahead of this clock is not open
    /// the same way, because the token claims to have been created at an instant that has not
    /// happened.
    /// </remarks>
    private Result<JsonWebToken, JwtValidationError> CompareTimestamps(
        JsonWebToken token,
        ValidationParameters parameters,
        DateTimeOffset? notBefore,
        DateTimeOffset? expiresAt,
        DateTimeOffset? issuedAt)
    {
        var utcNow = timeProvider.GetUtcNow();

        // Whatever bound the caller is held to has already been applied to the value it handed
        // over: a ceiling arriving as a second field is a ceiling somebody forgets to pass, and the
        // omission would read as a caller entitled to be looser rather than as the mistake it is.
        var refusal = parameters.ClockSkew.WhyRefused(utcNow, notBefore, expiresAt, issuedAt);

        return refusal is null
            ? token
            : new JwtValidationError(JwtError.InvalidToken, refusal);
    }
}
