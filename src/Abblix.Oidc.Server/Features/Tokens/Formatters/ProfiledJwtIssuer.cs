// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// The one door to <see cref="IJsonWebTokenCreator"/> for what this server signs or encrypts: it refuses to issue a
/// token whose signature or key management algorithm the security profile in force does not admit.
/// </summary>
/// <remarks>
/// FAPI 1.0 Part 2 section 8.6: "For JWS, both clients and authorization servers shall use PS256 or ES256 algorithms";
/// section 8.6.1: "For JWE, both clients and authorization servers shall not use the RSA1_5 algorithm"; FAPI 2.0 section
/// 5.4.1, "when creating or processing JWTs". The algorithm is judged as it is handed to the creator, after every path
/// has chosen it - a client's configuration, a key's declared algorithm, a deployment setting - so no path can reach the
/// creator with one the profile refuses. Each caller's own choice still prefers an admitted algorithm; this is what
/// holds when a choice did not.
/// <para>
/// Public, though nothing outside this library needs it, because the formatters that take it are public types with
/// public constructors, which the container requires.
/// </para>
/// </remarks>
/// <param name="creator">Issues the token once its algorithms are admitted.</param>
/// <param name="encryptionAlgorithms">Tells which keys may be used with a key management algorithm.</param>
public sealed class ProfiledJwtIssuer(IJsonWebTokenCreator creator, EncryptionAlgorithmsProvider encryptionAlgorithms)
{
    /// <summary>
    /// Issues <paramref name="token"/>, signed with <paramref name="signingKey"/> and, where an encryption key is given,
    /// encrypted to it, once <paramref name="profile"/> admits both algorithms.
    /// </summary>
    /// <param name="profile">The controls in force for what is issued.</param>
    /// <param name="token">The token, its header naming the signature algorithm.</param>
    /// <param name="signingKey">The key to sign with.</param>
    /// <param name="encryptionKey">The key to encrypt to, or null to issue a JWS.</param>
    /// <param name="keyEncryptionAlgorithm">The key management algorithm, where the token is encrypted.</param>
    /// <param name="contentEncryptionAlgorithm">The content encryption algorithm, where the token is encrypted.</param>
    /// <exception cref="AlgorithmRefusedByProfileException">The profile admits one of the algorithms not.</exception>
    public Task<string> IssueAsync(
        SecurityProfileRequirements profile,
        JsonWebToken token,
        JsonWebKey? signingKey,
        JsonWebKey? encryptionKey = null,
        string? keyEncryptionAlgorithm = null,
        string? contentEncryptionAlgorithm = null)
    {
        if (!profile.PermitsSigningAlgorithm(token.Header.Algorithm))
        {
            throw new AlgorithmRefusedByProfileException(
                $"The token would be signed with {token.Header.Algorithm}, which the security profile in force does " +
                "not admit",
                token.Header.Algorithm,
                encryptionKey: null);
        }

        if (encryptionKey is null)
            return creator.IssueAsync(token, signingKey);

        var keyManagement = keyEncryptionAlgorithm ?? EncryptionAlgorithms.KeyManagement.RsaOaep256;
        if (!profile.PermitsKeyManagementAlgorithm(keyManagement))
        {
            throw new AlgorithmRefusedByProfileException(
                $"The token would be encrypted with {keyManagement}, which the security profile in force forbids",
                keyManagement,
                encryptionKey);
        }

        return contentEncryptionAlgorithm is null
            ? creator.IssueAsync(token, signingKey, encryptionKey, keyManagement)
            : creator.IssueAsync(token, signingKey, encryptionKey, keyManagement, contentEncryptionAlgorithm);
    }

    /// <summary>
    /// Issues <paramref name="token"/> encrypted to <paramref name="encryptionKey"/> without a signature, as its claims
    /// set (<see cref="IJsonWebTokenCreator.EncryptClaimsAsync"/>), once <paramref name="profile"/> admits an unsigned
    /// token and the key management algorithm.
    /// </summary>
    /// <param name="profile">The controls in force for what is issued.</param>
    /// <param name="token">The token, its header naming no signature algorithm but none.</param>
    /// <param name="encryptionKey">The key to encrypt to.</param>
    /// <param name="keyEncryptionAlgorithm">The key management algorithm.</param>
    /// <param name="contentEncryptionAlgorithm">The content encryption algorithm.</param>
    /// <exception cref="AlgorithmRefusedByProfileException">The profile admits one of the algorithms not.</exception>
    public Task<string> EncryptClaimsAsync(
        SecurityProfileRequirements profile,
        JsonWebToken token,
        JsonWebKey encryptionKey,
        string keyEncryptionAlgorithm,
        string contentEncryptionAlgorithm)
    {
        if (!profile.PermitsSigningAlgorithm(SigningAlgorithms.None))
        {
            throw new AlgorithmRefusedByProfileException(
                "The token would be issued unsigned, which the security profile in force does not admit",
                SigningAlgorithms.None,
                encryptionKey: null);
        }

        if (!profile.PermitsKeyManagementAlgorithm(keyEncryptionAlgorithm))
        {
            throw new AlgorithmRefusedByProfileException(
                $"The token would be encrypted with {keyEncryptionAlgorithm}, which the security profile in force forbids",
                keyEncryptionAlgorithm,
                encryptionKey);
        }

        return creator.EncryptClaimsAsync(token, encryptionKey, keyEncryptionAlgorithm, contentEncryptionAlgorithm);
    }

    /// <summary>
    /// The key management algorithm a token would be encrypted to <paramref name="key"/> under, a key another party
    /// publishes, or null when it cannot be: the algorithm the key declares, else <paramref name="defaultAlgorithm"/>,
    /// provided this server performs it with a key of this type (<see cref="EncryptionAlgorithmsProvider.CanEncrypt"/>),
    /// and <paramref name="profile"/> admits it. RFC 8725 section 3.1 binds a key to the algorithm it declares, so a key published for signing, for an
    /// algorithm the host did not register, or of a type the default algorithm does not fit is passed over, as is one
    /// the profile forbids.
    /// </summary>
    /// <param name="profile">The controls in force for what is issued.</param>
    /// <param name="key">The published key.</param>
    /// <param name="defaultAlgorithm">The algorithm used for a key that declares none.</param>
    public string? EncryptionAlgorithmFor(SecurityProfileRequirements profile, JsonWebKey key, string defaultAlgorithm)
    {
        var algorithm = key.Algorithm ?? defaultAlgorithm;
        return creator.EncryptedResponseAlgorithmsSupported.Contains(algorithm, StringComparer.Ordinal) &&
               encryptionAlgorithms.CanEncrypt(key, algorithm) &&
               profile.PermitsKeyManagementAlgorithm(algorithm)
            ? algorithm
            : null;
    }
}
