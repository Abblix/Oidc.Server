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
/// The RSA key-size floor is a property of the deployment's keys, so it has to hold at the seam every
/// signing path crosses - not only inside the algorithm that signs in process.
/// </summary>
/// <remarks>
/// A key whose private half lives with an external custodian is public-only, so <c>RsaSigner</c> never
/// sees it: the composite routes it to the custodian backend instead. Without the floor at the seam, such
/// a deployment signs RS256 over an undersized modulus and then refuses to verify its own output, because
/// verification is always local and always goes through <c>RsaSigner</c>.
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

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => composite.SignAsync(PublicOnlyKey(BelowTheFloor), SigningAlgorithms.RS256, SampleData,
                TestContext.Current.CancellationToken));

        Assert.Contains(BelowTheFloor.ToString(), error.Message);
        Assert.Contains(JsonWebKeyExtensions.MinimumRsaKeyBits.ToString(), error.Message);

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
