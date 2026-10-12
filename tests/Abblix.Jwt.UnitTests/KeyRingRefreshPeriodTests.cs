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
/// The ring is refreshed at half its propagation window, never more often than once a second and never less often
/// than once a day, so every window a host may choose, none at all included, gives a period the timer accepts.
/// </summary>
public class KeyRingRefreshPeriodTests
{
    private const long Second = 1;
    private const long Hour = 60 * 60 * Second;
    private const long Day = 24 * Hour;

    [Theory]
    [InlineData(0, Second)]
    [InlineData(Second, Second)]
    [InlineData(2 * Hour, Hour)]
    [InlineData(2 * Day, Day)]
    [InlineData(365 * Day, Day)]
    public void TheRefreshPeriod_IsHalfTheWindow_KeptBetweenASecondAndADay(long windowSeconds, long periodSeconds)
    {
        var options = new KeyRingOptions { KeyRolloverPropagation = TimeSpan.FromSeconds(windowSeconds) };

        Assert.Equal(TimeSpan.FromSeconds(periodSeconds), options.RefreshPeriod);
    }

    [Fact]
    public void TheLongestWindow_GivesAPeriodTheTimerAccepts()
    {
        var options = new KeyRingOptions { KeyRolloverPropagation = TimeSpan.MaxValue };

        using var timer = new PeriodicTimer(options.RefreshPeriod);

        Assert.Equal(TimeSpan.FromDays(1), options.RefreshPeriod);
    }
}
