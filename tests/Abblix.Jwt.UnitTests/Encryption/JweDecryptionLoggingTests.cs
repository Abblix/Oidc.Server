// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// An inbound JWE that no key opens reaches the sender only as a refusal, so the server records it once, after every
/// candidate key, without saying which key failed or why.
/// </summary>
public class JweDecryptionLoggingTests
{
    // Longer than the part of a value the log keeps, so the record shows it was cut.
    private const int LongerThanAnyRecordKeeps = 1000;

    private readonly RecordingLogger<JweDecryptionLog> _logger = new();
    private readonly IJsonWebTokenEncryptor _encryptor;

    public JweDecryptionLoggingTests()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton<ILogger<JweDecryptionLog>>(_logger);
        _encryptor = services.BuildServiceProvider().GetRequiredService<IJsonWebTokenEncryptor>();
    }

    [Fact]
    public async Task TokenNoKeyOpens_IsRecordedOnceWithTheNumberOfKeysTried()
    {
        var jwtParts = await EncryptTo(NewKey("sender-key"));

        var result = await _encryptor.DecryptAsync(
            jwtParts,
            new[] { NewKey("sender-key"), NewKey("sender-key") }.ToAsyncEnumerable(),
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out _));
        var entry = Assert.Single(_logger.Entries);
        Assert.Equal(LogEvents.Jwt.NoDecryptionKeyOpened, entry.EventId);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal(2, entry.Value("KeyCount"));
        Assert.Equal(EncryptionAlgorithms.KeyManagement.Aes128KW, entry.Value("Algorithm")?.ToString());
        Assert.Equal(EncryptionAlgorithms.ContentEncryption.Aes128Gcm, entry.Value("EncryptionAlgorithm")?.ToString());
        Assert.Equal("sender-key", entry.Value("KeyId")?.ToString());
    }

    /// <summary>
    /// The header is the sender's text: an algorithm this server does not register is not written, and a key
    /// identifier reaches the record through <see cref="Sanitized"/>, cut short and without the line breaks that could
    /// pose as another record.
    /// </summary>
    [Fact]
    public async Task SendersHeaderValues_ReachTheRecordOnlyInASafeForm()
    {
        var jwtParts = await EncryptTo(NewKey("sender-key"));
        var keyId = "line\r\nforged record " + new string('k', LongerThanAnyRecordKeeps);
        jwtParts[0] = EncodeHeader("unknown-alg", EncryptionAlgorithms.ContentEncryption.Aes128Gcm, keyId);

        var result = await _encryptor.DecryptAsync(
            jwtParts,
            NewKey(keyId).ToAsync(),
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out _));
        var entry = Assert.Single(_logger.Entries);
        Assert.Equal(LogEvents.Jwt.NoDecryptionKeyOpened, entry.EventId);
        Assert.NotEqual("unknown-alg", entry.Value("Algorithm")?.ToString());
        var recorded = Assert.IsType<Sanitized>(entry.Value("KeyId")).ToString();
        Assert.DoesNotContain(recorded, char.IsControl);
        Assert.StartsWith("line", recorded);
        Assert.True(recorded.Length < keyId.Length);
    }

    /// <summary>
    /// A token refused before any key is tried has nothing to say about keys, so it leaves no record here.
    /// </summary>
    [Fact]
    public async Task TokenRefusedBeforeTheKeys_IsNotRecorded()
    {
        var key = NewKey("sender-key");
        var jwtParts = await EncryptTo(key);
        jwtParts[0] = EncodeHeader(EncryptionAlgorithms.KeyManagement.Aes128KW, "unknown-enc", "sender-key");

        var result = await _encryptor.DecryptAsync(jwtParts, key.ToAsync(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out _));
        Assert.Empty(_logger.Entries);
    }

    [Fact]
    public async Task TokenWithNoCandidateKey_IsRecordedOnce()
    {
        var jwtParts = await EncryptTo(NewKey("sender-key"));

        var result = await _encryptor.DecryptAsync(
            jwtParts,
            NewKey("another-key").ToAsync(),
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out _));
        var entry = Assert.Single(_logger.Entries);
        Assert.Equal(LogEvents.Jwt.NoDecryptionKey, entry.EventId);
        Assert.Equal(LogLevel.Warning, entry.Level);
    }

    [Fact]
    public async Task TokenAKeyOpens_IsNotRecorded()
    {
        var key = NewKey("sender-key");
        var jwtParts = await EncryptTo(key);

        var result = await _encryptor.DecryptAsync(
            jwtParts,
            new[] { NewKey("sender-key"), key }.ToAsyncEnumerable(),
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out _));
        Assert.Empty(_logger.Entries);
    }

    private async Task<string[]> EncryptTo(OctetJsonWebKey key)
    {
        var jwe = await _encryptor.EncryptAsync(
            Encoding.UTF8.GetBytes("inner token"),
            key,
            tokenType: null,
            EncryptionAlgorithms.KeyManagement.Aes128KW,
            EncryptionAlgorithms.ContentEncryption.Aes128Gcm,
            TestContext.Current.CancellationToken);
        return jwe.Split('.');
    }

    private static string EncodeHeader(string algorithm, string encryptionAlgorithm, string keyId)
    {
        var header = new JsonObject
        {
            ["alg"] = algorithm,
            ["enc"] = encryptionAlgorithm,
            ["kid"] = keyId,
        };
        return Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()));
    }

    private static OctetJsonWebKey NewKey(string keyId) => new()
    {
        KeyId = keyId,
        Algorithm = EncryptionAlgorithms.KeyManagement.Aes128KW,
        KeyValue = CryptoRandom.GetRandomBytes(16),
    };
}
