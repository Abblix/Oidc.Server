// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Threading;
using Abblix.Jwt.ExternalKeys;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The ring is refreshed on a timer at half its propagation window, and every window a host may choose, none at all
/// included, gives a period the timer accepts.
/// </summary>
public class KeyRingRefreshPeriodTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2 * 60 * 60 * 1000)]
    [InlineData(int.MaxValue)]
    public void EveryWindow_GivesAPeriodTheTimerAccepts(int windowMilliseconds)
    {
        var options = new KeyRingOptions { KeyRolloverPropagation = TimeSpan.FromMilliseconds(windowMilliseconds) * 100 };

        using var timer = new PeriodicTimer(options.RefreshPeriod);

        Assert.True(options.RefreshPeriod > TimeSpan.Zero);
    }

    [Fact]
    public void AnOrdinaryWindow_IsRefreshedTwicePerWindow()
    {
        var options = new KeyRingOptions { KeyRolloverPropagation = TimeSpan.FromHours(2) };

        Assert.Equal(TimeSpan.FromHours(1), options.RefreshPeriod);
    }
}
