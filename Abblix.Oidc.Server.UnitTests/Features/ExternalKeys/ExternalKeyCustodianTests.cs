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
/// Verifies that <see cref="ExternalKeyCustodian"/> is a faithful passthrough to the <see cref="IExternalKeyStore"/>:
/// it forwards the kid, algorithm and payload of every private operation, and surfaces the store's rejection when
/// the store does not provision an algorithm. The store, not the custodian, owns algorithm support, so one
/// custodian serves any store.
/// </summary>
public class ExternalKeyCustodianTests
{
    [Fact]
    public async Task SignAsync_ForwardsKidAlgorithmAndData_ToStore()
    {
        var signature = new byte[] { 1, 2, 3 };
        var store = new Mock<IExternalKeyStore>();
        store.Setup(s => s.SignAsync("kid", SigningAlgorithms.PS384, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(signature);
        var custodian = new ExternalKeyCustodian(store.Object);

        var result = await custodian.SignAsync(
            "kid", SigningAlgorithms.PS384, new byte[] { 9 }, TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
        store.Verify(
            s => s.SignAsync("kid", SigningAlgorithms.PS384, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task UnwrapKeyAsync_ForwardsKidAlgorithmAndCiphertext_ToStore()
    {
        var plaintext = new byte[] { 4, 5, 6 };
        var store = new Mock<IExternalKeyStore>();
        store.Setup(s => s.DecryptAsync(
                "kid", EncryptionAlgorithms.KeyManagement.RsaOaep, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(plaintext);
        var custodian = new ExternalKeyCustodian(store.Object);

        var result = await custodian.UnwrapKeyAsync(
            "kid", EncryptionAlgorithms.KeyManagement.RsaOaep, new JsonWebTokenHeader(new JsonObject()),
            new byte[] { 1 }, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, result);
    }

    [Fact]
    public async Task AgreeKeyAsync_ForwardsToStore()
    {
        var sharedSecret = new byte[] { 7, 7 };
        var store = new Mock<IExternalKeyStore>();
        store.Setup(s => s.AgreeKeyAsync(
                "kid", "ECDH-ES", It.IsAny<JsonWebKey>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(sharedSecret);
        var custodian = new ExternalKeyCustodian(store.Object);

        var result = await custodian.AgreeKeyAsync(
            "kid", "ECDH-ES", new EllipticCurveJsonWebKey(), TestContext.Current.CancellationToken);

        Assert.Equal(sharedSecret, result);
    }

    [Fact]
    public async Task SignAsync_PropagatesTheStoresRejection_OfAnUnsupportedAlgorithm()
    {
        var store = new Mock<IExternalKeyStore>();
        store.Setup(s => s.SignAsync("kid", "ES256", It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new NotSupportedException());
        var custodian = new ExternalKeyCustodian(store.Object);

        await Assert.ThrowsAsync<NotSupportedException>(() => custodian
            .SignAsync("kid", "ES256", new byte[] { 9 }, TestContext.Current.CancellationToken).AsTask());
    }
}
