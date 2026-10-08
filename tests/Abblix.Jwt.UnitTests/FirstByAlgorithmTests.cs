// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Picking the key to sign or encrypt with: the first key in the order handed down that can perform the
/// algorithm, by declaring it or, declaring none, by its material.
/// </summary>
public class FirstByAlgorithmTests
{
    private static async IAsyncEnumerable<JsonWebKey> Sequence(params JsonWebKey[] keys)
    {
        foreach (var key in keys)
        {
            await Task.Yield();
            yield return key;
        }
    }

    /// <summary>
    /// A key declaring another algorithm is passed over even when its material could perform the requested one, and
    /// an undeclared key qualifies by what its material can do, in the order the keys arrive rather than by whether
    /// they declare an algorithm.
    /// </summary>
    [Fact]
    public async Task TheFirstKeyAbleToPerformTheAlgorithm_IsChosen()
    {
        var rsaDeclaringAnother = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS384);
        var undeclaredRsa = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        undeclaredRsa.Algorithm = null;
        var declaredRsa = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

        var chosen = await Sequence(rsaDeclaringAnother, undeclaredRsa, declaredRsa)
            .FirstByAlgorithmAsync(SigningAlgorithms.RS256);

        Assert.Same(undeclaredRsa, chosen);
    }

    /// <summary>
    /// An undeclared key whose material cannot perform the algorithm does not qualify, and nothing qualifying fails
    /// loudly rather than signing with no key.
    /// </summary>
    [Fact]
    public async Task NoKeyAbleToPerformTheAlgorithm_Throws()
    {
        var undeclaredRsa = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        undeclaredRsa.Algorithm = null;

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Sequence(undeclaredRsa).FirstByAlgorithmAsync(SigningAlgorithms.ES256));
    }

    [Fact]
    public async Task APinnedKeyIdMatchingNoKey_Throws()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        key.KeyId = "current";

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Sequence(key).FirstByAlgorithmAsync(SigningAlgorithms.RS256, "retired"));
    }

    /// <summary>
    /// A pinned key that cannot perform the required algorithm is refused at selection rather than at signing.
    /// </summary>
    [Fact]
    public async Task APinnedKeyIdOfAKeyUnableToPerformTheAlgorithm_Throws()
    {
        var ecdsa = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);
        ecdsa.KeyId = "k";

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Sequence(ecdsa).FirstByAlgorithmAsync(SigningAlgorithms.RS256, "k"));
    }

    /// <summary>
    /// A pinned key id matching no key fails even with no algorithm to satisfy, so an encryption pinned to a key
    /// that is gone never falls back to issuing the token unencrypted.
    /// </summary>
    [Fact]
    public async Task APinnedKeyIdMatchingNoKeyWithoutAnAlgorithm_Throws()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
        key.KeyId = "current";

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Sequence(key).FirstByAlgorithmAsync(algorithm: null, keyId: "retired"));
    }

    [Fact]
    public async Task APinnedKeyId_ChoosesThatKey()
    {
        var current = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        current.KeyId = "current";
        var next = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        next.KeyId = "next";

        Assert.Same(next, await Sequence(current, next).FirstByAlgorithmAsync(SigningAlgorithms.RS256, "next"));
    }

    /// <summary>
    /// An unsigned token needs no key, so <c>none</c> answers none whatever the keys.
    /// </summary>
    [Fact]
    public async Task TheNoneAlgorithm_ChoosesNoKey()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

        Assert.Null(await Sequence(key).FirstByAlgorithmAsync(SigningAlgorithms.None));
        Assert.Null(await Sequence(key).FirstByAlgorithmAsync(SigningAlgorithms.None, keyId: null));
    }

    /// <summary>
    /// With neither an algorithm nor a key id to satisfy, an empty sequence is not a failure: there is simply no key.
    /// </summary>
    [Fact]
    public async Task NoFilterOverNoKeys_ChoosesNoKey()
    {
        Assert.Null(await Sequence().FirstByAlgorithmAsync(algorithm: null, keyId: null));
    }

    /// <summary>
    /// Without an algorithm to sign with there is nothing to select, whatever the keys.
    /// </summary>
    [Fact]
    public async Task NoAlgorithm_ChoosesNoKey()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

        Assert.Null(await Sequence(key).FirstByAlgorithmAsync(algorithm: null));
    }
}
