// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// The out-of-the-box signer: compact JWS through the Abblix JWT core, with the signing key from
/// the source the host configured.
/// </summary>
/// <remarks>
/// The key source is asked per signing rather than once, so key rotation on the host's side takes
/// effect on the next token instead of the next restart. The signing algorithm follows the key,
/// and this signer writes it into the header rather than letting the core derive it, so that what
/// was judged against the allowlist is what the token is signed with.
/// </remarks>
/// <param name="creator">The JWT core's token creator.</param>
/// <param name="signingKeySource">Supplies the private key each signing uses.</param>
/// <param name="allowedAlgorithms">What this deployment will sign with.</param>
public sealed class DefaultSecurityEventTokenSigner(
    IJsonWebTokenCreator creator,
    Func<CancellationToken, Task<JsonWebKey>> signingKeySource,
    IReadOnlySet<string> allowedAlgorithms) : ISecurityEventTokenSigner
{
    /// <inheritdoc />
    /// <exception cref="InvalidOperationException">The key names no algorithm, or one this deployment
    /// does not allow.</exception>
    public async Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
    {
        var signingKey = await signingKeySource(cancellationToken);

        // Refused here rather than left to the key, because the core's rule for a key that names no
        // algorithm and a header that names none either is to fall through to "none" - which would emit
        // an event stating nothing about who issued it. A key whose algorithm this deployment did not
        // allow is the same failure with a name on it: the host configured a policy and a key that
        // disagree, and the honest moment to say so is before a receiver has to.
        if ((signingKey.Algorithm ?? token.Token.Header.Algorithm) is not { } algorithm ||
            !allowedAlgorithms.Contains(algorithm))
        {
            throw new InvalidOperationException(
                $"A security event token cannot be signed with '{signingKey.Algorithm ?? "no algorithm"}': "
                + $"this deployment allows {string.Join(", ", allowedAlgorithms)}. Configure a signing key "
                + $"declaring one of those, or widen "
                + $"{nameof(SecurityEventsOptions)}.{nameof(SecurityEventsOptions.AllowedSigningAlgorithms)}.");
        }

        // Written into the header so the core cannot resolve anything else: its rule prefers the key's
        // algorithm and falls back to the header's, and agreeing with both is what keeps the judgement
        // above and the signature below from being about different algorithms.
        token.Token.Header.Algorithm = algorithm;

        return await creator.IssueAsync(token.Token, signingKey);
    }
}
