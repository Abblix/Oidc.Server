// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

// The periods a minted key ring is registered with: refused when the ring could not rotate on them, and honored to
// their full length when they are long
public sealed partial class KeyRingTests
{
    /// <summary>
    /// A ring that never forgets a retired key, given as the longest span there is, keeps both keys across a
    /// rotation instead of failing on the arithmetic of its own periods.
    /// </summary>
    [Fact]
    public async Task ARingThatNeverForgets_KeepsTheRetiredKey_AcrossARotation()
    {
        var shared = new FakeStore();

        var (first, _) = CreateRing(shared, keepRetiredFor: TimeSpan.MaxValue);
        await first.RefreshAsync(TestContext.Current.CancellationToken);

        var (later, _) = CreateRing(shared, now: Now.AddDays(90), keepRetiredFor: TimeSpan.MaxValue);
        await later.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.Equal(2, shared.Entries.Count);
    }

    /// <summary>
    /// A policy the ring cannot rotate on stops the host while it registers the ring: a rotation period that is not
    /// positive divides the rotation grid by nothing, and a negative retention drops a key while it still signs.
    /// </summary>
    [Theory]
    [InlineData(0, null)]
    [InlineData(-1, null)]
    [InlineData(30, -1)]
    public void APolicyTheRingCannotRotateOn_IsRefusedAtRegistration(int rotateEveryDays, int? keepRetiredForHours)
    {
        var policy = new MintedKeys
        {
            KeyEncryptionKeyName = KeyEncryptionKeyName,
            RotateEvery = TimeSpan.FromDays(rotateEveryDays),
            KeepRetiredFor = keepRetiredForHours is { } hours ? TimeSpan.FromHours(hours) : null,
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => new ServiceCollection().AddKeyRing(policy));
    }
}
