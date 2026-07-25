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
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Interfaces;

/// <summary>
/// Verifies the JWKS publication set: signing public keys are marked <c>use=sig</c>, the server's asymmetric
/// encryption public keys are marked <c>use=enc</c>, a symmetric encryption key (no public half)
/// is omitted, and, as a last-resort backstop, any key that still carries private material is stripped to
/// its public half and logged before it can leave the publication boundary.
/// </summary>
public class AuthServiceKeysProviderExtensionsTests
{
    [Fact]
    public async Task GetPublishedKeysAsync_AddsAsymmetricEncryptionKeysMarkedEnc_AndOmitsSymmetric()
    {
        var signingKey = JsonWebKeyFactory
            .CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)
            .Sanitize(includePrivateKeys: false);
        signingKey.Usage = null; // prove the publication marks it use=sig rather than relying on config

        var encryptionKey = JsonWebKeyFactory
            .CreateRsa(PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256)
            .Sanitize(includePrivateKeys: false);
        encryptionKey.Usage = null; // prove the publication marks it use=enc rather than relying on config

        // A symmetric key published public-only has no key bytes and no public half, so it cannot be shared.
        var symmetricKey = new OctetJsonWebKey { KeyId = "sym-enc" };

        var provider = new Mock<IAuthServiceKeysProvider>();
        provider.Setup(p => p.GetSigningKeys()).Returns(new[] { signingKey }.ToAsyncEnumerable());
        provider.Setup(p => p.GetEncryptionKeys())
            .Returns(new JsonWebKey[] { encryptionKey, symmetricKey }.ToAsyncEnumerable());

        var published = await provider.Object.GetPublishedKeysAsync(NullLogger<IAuthServiceKeysProvider>.Instance);

        // The signing key is published and marked use=sig.
        Assert.Contains(published, k => k.KeyId == signingKey.KeyId && k.Usage == PublicKeyUsages.Signature);

        // The asymmetric encryption key is published and marked use=enc.
        Assert.Contains(published, k => k.KeyId == encryptionKey.KeyId && k.Usage == PublicKeyUsages.Encryption);

        // The symmetric key has no public half and is omitted; no private or secret material is published.
        Assert.DoesNotContain(published, k => k.KeyId == "sym-enc");
        Assert.All(published, k => Assert.False(k.HasPrivateKey));
    }

    [Fact]
    public async Task GetPublishedKeysAsync_NeverPublishesSymmetricKey_EvenWhenProviderReturnsItsSecret()
    {
        // The dangerous case: a misbehaving provider hands the publication path a symmetric encryption key that
        // still carries its secret bytes. A symmetric key has no public half, so it must never reach the public
        // JWKS - not even as an empty shell, and never carrying its secret.
        var secretBearingSymmetricKey = new OctetJsonWebKey
        {
            KeyId = "sym-enc",
            KeyValue = [1, 2, 3, 4, 5, 6, 7, 8],
        };
        Assert.True(secretBearingSymmetricKey.HasPrivateKey); // precondition: the secret is present on the way in

        var provider = new Mock<IAuthServiceKeysProvider>();
        provider.Setup(p => p.GetSigningKeys()).Returns(Array.Empty<JsonWebKey>().ToAsyncEnumerable());
        provider.Setup(p => p.GetEncryptionKeys())
            .Returns(new JsonWebKey[] { secretBearingSymmetricKey }.ToAsyncEnumerable());

        var logger = new CapturingLogger<IAuthServiceKeysProvider>();

        var published = await provider.Object.GetPublishedKeysAsync(logger);

        // The symmetric key is fully omitted: nothing reaches the set, by kid or by type.
        Assert.DoesNotContain(published, k => k.KeyId == "sym-enc");
        Assert.DoesNotContain(published, k => k is OctetJsonWebKey);

        // Nothing carrying private or secret material is ever published.
        Assert.All(published, k => Assert.False(k.HasPrivateKey));

        // Handing secret material to the publication boundary is surfaced as a warning for the operator.
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task GetPublishedKeysAsync_PublishesBothRoles_WhenOneKeyServesSigningAndEncryption()
    {
        // A host returns the SAME key from both roles (distinct kids per use is the best practice, but nothing
        // forbids reuse). The publication must stay faithful and safe: the key appears in each role, public-only,
        // and the two entries are told apart by use (a shared kid carrying different use).
        var dualUseKey = JsonWebKeyFactory
            .CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)
            .Sanitize(includePrivateKeys: false);

        var provider = new Mock<IAuthServiceKeysProvider>();
        provider.Setup(p => p.GetSigningKeys()).Returns(new[] { dualUseKey }.ToAsyncEnumerable());
        provider.Setup(p => p.GetEncryptionKeys()).Returns(new[] { dualUseKey }.ToAsyncEnumerable());

        var published = await provider.Object.GetPublishedKeysAsync(NullLogger<IAuthServiceKeysProvider>.Instance);

        // Both roles are represented, each public-only, sharing the kid and distinguished by use.
        var entries = published.Where(k => k.KeyId == dualUseKey.KeyId).ToArray();
        Assert.Equal(2, entries.Length);
        Assert.Contains(entries, k => k.Usage == PublicKeyUsages.Signature);
        Assert.Contains(entries, k => k.Usage == PublicKeyUsages.Encryption);
        Assert.All(published, k => Assert.False(k.HasPrivateKey));
    }

    [Fact]
    public async Task GetPublishedKeysAsync_StripsPrivateMaterialAndWarns_WhenProviderLeaksPrivateKey()
    {
        // A misbehaving provider hands the publication path a signing key that still carries its private half.
        var privateBearingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        Assert.True(privateBearingKey.HasPrivateKey); // precondition: private material is present on the way in

        var provider = new Mock<IAuthServiceKeysProvider>();
        provider.Setup(p => p.GetSigningKeys()).Returns(new[] { privateBearingKey }.ToAsyncEnumerable());
        provider.Setup(p => p.GetEncryptionKeys()).Returns(Array.Empty<JsonWebKey>().ToAsyncEnumerable());

        var logger = new CapturingLogger<IAuthServiceKeysProvider>();

        var published = await provider.Object.GetPublishedKeysAsync(logger);

        // The key keeps its identity but is stripped to its public half before publication.
        var publishedKey = Assert.Single(published);
        Assert.Equal(privateBearingKey.KeyId, publishedKey.KeyId);
        Assert.False(publishedKey.HasPrivateKey);

        // The near-leak is surfaced as a warning so an operator can fix the offending provider.
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Warning);
    }

    /// <summary>
    /// Minimal <see cref="ILogger{TCategoryName}"/> that records the level of each entry, so a test can
    /// assert a warning was emitted without coupling to the <c>[LoggerMessage]</c> call shape.
    /// </summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, EventId EventId)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, eventId));
    }
}
