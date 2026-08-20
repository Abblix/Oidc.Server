// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ReusePrevention;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ReusePrevention;

/// <summary>
/// Unit tests for <see cref="AuthorizationValueReuseDetector"/> covering the RFC 9700 Section 2.1.1
/// constant-value detection: a value recorded once is reported as reused, distinct values/kinds/clients stay
/// independent, and the whole mechanism is inert unless the detection interval is configured.
/// </summary>
public class AuthorizationValueReuseDetectorTests
{
    private const string CodeChallenge = "code_challenge";
    private const string Nonce = "nonce";

    private static AuthorizationValueReuseDetector CreateDetector(TimeSpan? interval)
        => new(
            new InMemoryEntityStorage(),
            new EntityStorageKeyFactory(),
            Options.Create(new OidcOptions { PkceAndNonceReuseDetectionInterval = interval }));

    [Fact]
    public async Task Enabled_RecordThenCheck_ReportsReused()
    {
        var detector = CreateDetector(TimeSpan.FromMinutes(5));

        // A value not yet recorded is fresh; after recording, the same value is flagged as reused.
        Assert.False(await detector.IsReusedAsync("c1", CodeChallenge, "value-1"));
        await detector.RecordAsync("c1", CodeChallenge, "value-1");
        Assert.True(await detector.IsReusedAsync("c1", CodeChallenge, "value-1"));

        // A different value, a different kind, and a different client are all independent.
        Assert.False(await detector.IsReusedAsync("c1", CodeChallenge, "value-2"));
        Assert.False(await detector.IsReusedAsync("c1", Nonce, "value-1"));
        Assert.False(await detector.IsReusedAsync("c2", CodeChallenge, "value-1"));
    }

    [Fact]
    public async Task Disabled_IsInert()
    {
        var detector = CreateDetector(interval: null);

        await detector.RecordAsync("c1", CodeChallenge, "value-1");

        // Nothing is recorded and nothing is flagged while detection is off.
        Assert.False(await detector.IsReusedAsync("c1", CodeChallenge, "value-1"));
    }

    private sealed class InMemoryEntityStorage : IEntityStorage
    {
        private readonly Dictionary<string, object?> _store = new();

        public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
        {
            _store[key] = value;
            return Task.CompletedTask;
        }

        public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
        {
            var found = _store.TryGetValue(key, out var value);
            if (found && removeOnRetrieval)
                _store.Remove(key);

            return Task.FromResult(found ? (T?)value : default);
        }

        public Task RemoveAsync(string key, CancellationToken? token = null)
        {
            _store.Remove(key);
            return Task.CompletedTask;
        }
    }
}
