// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The times a key ring's steps read (Parameter Object): the clock, the rotation period, how long a new key takes to
/// reach every consumer, and how long a retired one is kept.
/// </summary>
/// <param name="policy">The ring's rotation policy.</param>
/// <param name="options">The settings shared by every ring.</param>
/// <param name="timeProvider">The clock.</param>
internal sealed class KeyRingSchedule(MintedKeys policy, IOptions<KeyRingOptions> options, TimeProvider timeProvider)
{
    /// <summary>The current instant, read from the ring's clock.</summary>
    public DateTimeOffset Now => timeProvider.GetUtcNow();

    /// <summary>How often a new key is minted.</summary>
    public TimeSpan RotateEvery => policy.RotateEvery;

    /// <summary>
    /// The start of the rotation period the clock is in: a coordinate on the grid, not a timestamp, so every pod
    /// reading the clock within one period computes the same instant.
    /// </summary>
    public DateTimeOffset CurrentPeriodStart
    {
        get
        {
            var periods = Now.UtcTicks / RotateEvery.Ticks;
            return new DateTimeOffset(periods * RotateEvery.Ticks, TimeSpan.Zero);
        }
    }

    /// <summary>How long a new key takes to reach every consumer before it produces.</summary>
    public TimeSpan Propagation => options.Value.KeyRolloverPropagation;

    /// <summary>How long a key is kept once its successor has taken over, a rotation period unless set.</summary>
    public TimeSpan KeepRetiredFor => policy.KeepRetiredFor ?? policy.RotateEvery;
}
