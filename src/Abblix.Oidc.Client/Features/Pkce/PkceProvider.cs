// Abblix OIDC Client Library
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

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Utils;

namespace Abblix.Oidc.Client.Features.Pkce;

/// <summary>
/// Creates the PKCE values of an authorization request, using the SHA-256 transformation of RFC 7636.
/// </summary>
public sealed class PkceProvider : IPkceProvider
{
    /// <summary>
    /// The number of random bytes behind a verifier.
    /// </summary>
    /// <remarks>
    /// RFC 7636 section 4.1 allows a verifier of 43 to 128 characters and recommends exactly this: 32 bytes
    /// from a cryptographic generator, encoded as base64url, which lands on 43 characters.
    /// </remarks>
    private const int VerifierByteCount = 32;

    private readonly IProviderMetadataProvider _metadataProvider;

    /// <summary>
    /// Creates the provider.
    /// </summary>
    public PkceProvider(IProviderMetadataProvider metadataProvider) => _metadataProvider = metadataProvider;

    /// <inheritdoc />
    public async Task<PkceParameters> CreateAsync(CancellationToken cancellationToken = default)
    {
        await EnsureProviderSupportsSha256Async(cancellationToken);

        var verifier = Base64Url.EncodeToString(CryptoRandom.GetRandomBytes(VerifierByteCount));
        var challenge = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        return new PkceParameters(verifier, challenge, CodeChallengeMethods.S256);
    }

    /// <summary>
    /// Refuses to build a request for a provider that does not advertise the SHA-256 transformation.
    /// </summary>
    /// <remarks>
    /// RFC 7636 also defines a `plain` transformation, where the challenge is the verifier itself. Falling
    /// back to it when the provider looks unable to do better is the PKCE downgrade: anyone who can read the
    /// authorization request then holds the verifier, and the protection is gone while still appearing to be
    /// in place. So the client stops instead, loudly, and the operator decides.
    ///
    /// A provider that advertises nothing is given the benefit of the doubt: the member is optional, plenty
    /// of providers support SHA-256 without listing it, and a request the provider cannot honour fails there
    /// rather than silently weakening anything here.
    /// </remarks>
    private async Task EnsureProviderSupportsSha256Async(CancellationToken cancellationToken)
    {
        var metadata = await _metadataProvider.GetMetadataAsync(cancellationToken);

        if (metadata.CodeChallengeMethodsSupported is not { Count: > 0 } supported)
            return;

        if (!supported.Contains(CodeChallengeMethods.S256, StringComparer.Ordinal))
            throw new PkceException(
                $"The OpenID Provider '{metadata.Issuer}' advertises code challenge methods "
                + $"[{string.Join(", ", supported)}], which do not include '{CodeChallengeMethods.S256}'. This client does "
                + "not fall back to a weaker transformation, because doing so would leave the request looking "
                + "protected while it is not.");
    }
}
