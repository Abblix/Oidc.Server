// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
