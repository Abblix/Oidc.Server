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
/// as the core derives it, which keeps the "alg" header and the key material from disagreeing.
/// </remarks>
/// <param name="creator">The JWT core's token creator.</param>
/// <param name="signingKeySource">Supplies the private key each signing uses.</param>
public sealed class DefaultSecurityEventTokenSigner(
    IJsonWebTokenCreator creator,
    Func<CancellationToken, Task<JsonWebKey>> signingKeySource) : ISecurityEventTokenSigner
{
    /// <inheritdoc />
    public async Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
    {
        var signingKey = await signingKeySource(cancellationToken);

        return await creator.IssueAsync(token.Token, signingKey);
    }
}
