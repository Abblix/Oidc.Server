// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using Abblix.Jwt.Signing;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The RSA key-size floor is a property of the deployment's keys, so it holds at BOTH doors into
/// signing - neither of which is always present.
/// </summary>
/// <remarks>
/// <c>CompositeSigner</c> is registered only when a custodian is wired; a deployment with nothing but
/// <c>AddJsonWebTokens()</c> resolves <c>IDataSigner</c> to <c>LocalKeySigner</c> and this class does not
/// exist in it. So neither guard is redundant, and deleting the one in <c>RsaSigner</c> because this test
/// passes would open the configuration most deployments run.
///
/// What this door adds: a key whose private half lives with an external custodian is public-only, so
/// <c>RsaSigner</c> never sees it FOR SIGNING - the composite routes it to the custodian backend instead.
/// It does see that key for every VERIFICATION, which is always local. So without the floor here, such a
/// deployment signs RS256 over an undersized modulus and then refuses to verify its own output.
/// </remarks>
public class CompositeSignerKeyFloorTests
{
    private static readonly byte[] SampleData = "the quick brown fox"u8.ToArray();

    /// <summary>
    /// An undersized key that every RSA signing algorithm can still use, for the reason
    /// <see cref="RsaSignerTests"/> gives: PSS with SHA-512 cannot sign with 1024 bits at all.
    /// </summary>
    private const int BelowTheFloor = 1536;

    [Fact]
    public async Task SignAsync_AnExternalKeyBelowTheFloor_IsRefusedAtTheSeam()
    {
        var custodian = new RecordingCustodian();
        var composite = new CompositeSigner([new ExternalKeys.ExternalKeySigner(custodian)]);

        var error = await Assert.ThrowsAsync<ArgumentException>(
            () => composite.SignAsync(PublicOnlyKey(BelowTheFloor), SigningAlgorithms.RS256, SampleData,
                TestContext.Current.CancellationToken));

        Assert.Contains(BelowTheFloor.ToString(), error.Message);
        Assert.Contains(JsonWebKeyExtensions.MinimumRsaKeyBits.ToString(), error.Message);

        // The COMPOSED sentence, not the pieces. Two functions can each return something correct and
        // still produce a message that says "per RFC 7518" twice, which is exactly what happened: the
        // citation phrase carries those words and the sentence around it once wrote them as well.
        Assert.Contains("per RFC 7518 Section 3.3", error.Message);
        Assert.DoesNotContain("per RFC 7518 per", error.Message);

        // The refusal has to happen BEFORE the custodian is asked, or a hardware module has already
        // performed the operation this deployment cannot verify.
        Assert.False(custodian.WasAsked);
    }

    /// <summary>
    /// The control. Without it, a seam that refused every external key would pass the test above.
    /// </summary>
    [Fact]
    public async Task SignAsync_AnExternalKeyAtTheFloor_ReachesTheCustodian()
    {
        var custodian = new RecordingCustodian();
        var composite = new CompositeSigner([new ExternalKeys.ExternalKeySigner(custodian)]);

        var signature = await composite.SignAsync(
            PublicOnlyKey(JsonWebKeyExtensions.MinimumRsaKeyBits), SigningAlgorithms.RS256, SampleData,
            TestContext.Current.CancellationToken);

        Assert.True(custodian.WasAsked);
        Assert.NotEmpty(signature);
    }

    /// <summary>
    /// An RSA key carrying no <c>alg</c> resolves to <c>SigningAlgorithms.None</c>, which has no floor
    /// section of its own. The seam must still refuse it for its SIZE, and say so.
    /// </summary>
    /// <remarks>
    /// Building the citation by a method that throws on an unknown algorithm would replace this refusal
    /// with a complaint about the citation, on the one path where the operator most needs the size.
    /// </remarks>
    [Fact]
    public async Task SignAsync_AnUndersizedKeyWithNoAlgorithm_IsStillRefusedForItsSize()
    {
        var custodian = new RecordingCustodian();
        var composite = new CompositeSigner([new ExternalKeys.ExternalKeySigner(custodian)]);

        var error = await Assert.ThrowsAsync<ArgumentException>(
            () => composite.SignAsync(PublicOnlyKey(BelowTheFloor), SigningAlgorithms.None, SampleData,
                TestContext.Current.CancellationToken));

        Assert.Contains(BelowTheFloor.ToString(), error.Message);
        Assert.Contains(JsonWebKeyExtensions.MinimumRsaKeyBits.ToString(), error.Message);

        // The arm with no section of its own has to read as a sentence too - stated positively, because
        // the negative form cannot fail here: this arm never begins with "per", so a doubled prefix
        // upstream leaves it green while breaking the other one.
        Assert.Contains("bits for RSA signatures", error.Message);

        Assert.False(custodian.WasAsked);
    }

    private static RsaJsonWebKey PublicOnlyKey(int bits)
    {
        using var rsa = RSA.Create(bits);
        var parameters = rsa.ExportParameters(false);

        return new RsaJsonWebKey
        {
            KeyId = "custodian-handle",
            Usage = PublicKeyUsages.Signature,
            Algorithm = SigningAlgorithms.RS256,
            Modulus = parameters.Modulus,
            Exponent = parameters.Exponent,
        };
    }

    private sealed class RecordingCustodian : ExternalKeys.IKeyCustodian
    {
        public bool WasAsked { get; private set; }

        public Task<byte[]> SignAsync(
            string keyId, string algorithm, byte[] data, CancellationToken cancellationToken)
        {
            WasAsked = true;
            return Task.FromResult(new byte[] { 1, 2, 3 });
        }

        // The rest of the seam, which these tests do not exercise: a custodian that never answers them is
        // still a custodian for the purpose of asking whether signing was reached.
        public Task<byte[]?> UnwrapKeyAsync(
            string keyId, string algorithm, JsonWebTokenHeader header, byte[] encryptedKey,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<byte[]> AgreeKeyAsync(
            string keyId, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(
            string keyName, CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }
}
