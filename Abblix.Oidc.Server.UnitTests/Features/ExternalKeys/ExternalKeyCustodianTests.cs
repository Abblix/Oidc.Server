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

using System;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ExternalKeys;

/// <summary>
/// Verifies the algorithm gate of <see cref="ExternalKeyCustodian"/>: the RSA operations forward to the store,
/// while an unsupported algorithm is rejected before the store is touched, and ECDH-ES agreement is unreachable.
/// One custodian serves any <see cref="IExternalKeyStore"/>, so this covers the Vault and Azure packages alike.
/// </summary>
public class ExternalKeyCustodianTests
{
    [Fact]
    public async Task SignAsync_ForwardsRs256_ToStore()
    {
        var signature = new byte[] { 1, 2, 3 };
        var store = new Mock<IExternalKeyStore>();
        store.Setup(s => s.SignAsync("kid", It.IsAny<byte[]>(), It.IsAny<CancellationToken>())).ReturnsAsync(signature);
        var custodian = new ExternalKeyCustodian(store.Object);

        var result = await custodian.SignAsync(
            "kid", SigningAlgorithms.RS256, new byte[] { 9 }, TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
    }

    [Fact]
    public async Task SignAsync_RejectsNonRs256_WithoutTouchingStore()
    {
        // A strict mock throws on any call, so the assertion also proves the guard fires before the store is used.
        var store = new Mock<IExternalKeyStore>(MockBehavior.Strict);
        var custodian = new ExternalKeyCustodian(store.Object);

        await Assert.ThrowsAsync<NotSupportedException>(() => custodian
            .SignAsync("kid", "ES256", new byte[] { 9 }, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task UnwrapKeyAsync_ForwardsRsaOaep256_ToStore()
    {
        var plaintext = new byte[] { 4, 5, 6 };
        var store = new Mock<IExternalKeyStore>();
        store.Setup(s => s.DecryptAsync("kid", It.IsAny<byte[]>(), It.IsAny<CancellationToken>())).ReturnsAsync(plaintext);
        var custodian = new ExternalKeyCustodian(store.Object);

        var result = await custodian.UnwrapKeyAsync(
            "kid", EncryptionAlgorithms.KeyManagement.RsaOaep256,
            new JsonWebTokenHeader(new JsonObject()), new byte[] { 1 }, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, result);
    }

    [Fact]
    public async Task UnwrapKeyAsync_RejectsNonRsaOaep256_WithoutTouchingStore()
    {
        var store = new Mock<IExternalKeyStore>(MockBehavior.Strict);
        var custodian = new ExternalKeyCustodian(store.Object);

        await Assert.ThrowsAsync<NotSupportedException>(() => custodian.UnwrapKeyAsync(
            "kid", "RSA1_5", new JsonWebTokenHeader(new JsonObject()),
            new byte[] { 1 }, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public void AgreeKeyAsync_IsNotSupported()
    {
        var store = new Mock<IExternalKeyStore>(MockBehavior.Strict);
        var custodian = new ExternalKeyCustodian(store.Object);

        Assert.Throws<NotSupportedException>(() => _ = custodian.AgreeKeyAsync(
            "kid", "ECDH-ES", new RsaJsonWebKey(), TestContext.Current.CancellationToken));
    }
}
