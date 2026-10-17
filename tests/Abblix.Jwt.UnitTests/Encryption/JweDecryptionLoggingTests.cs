// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text;
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
    private readonly RecordingLogger<JweDecryption> _logger = new();
    private readonly IJsonWebTokenEncryptor _encryptor;

    public JweDecryptionLoggingTests()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton<ILogger<JweDecryption>>(_logger);
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

    private static OctetJsonWebKey NewKey(string keyId) => new()
    {
        KeyId = keyId,
        Algorithm = EncryptionAlgorithms.KeyManagement.Aes128KW,
        KeyValue = CryptoRandom.GetRandomBytes(16),
    };

    private sealed record Entry(LogLevel Level, int EventId, IReadOnlyList<KeyValuePair<string, object?>> State)
    {
        public object? Value(string name) => State.Single(pair => pair.Key == name).Value;
    }

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        private readonly List<Entry> _entries = [];

        public IReadOnlyList<Entry> Entries
        {
            get
            {
                lock (_entries)
                    return [.. _entries];
            }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var values = state as IReadOnlyList<KeyValuePair<string, object?>> ?? [];
            lock (_entries)
                _entries.Add(new Entry(logLevel, eventId.Id, values));
        }
    }
}
