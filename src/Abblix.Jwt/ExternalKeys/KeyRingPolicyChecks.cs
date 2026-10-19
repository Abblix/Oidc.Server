// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Refuses a key ring policy whose periods the ring cannot rotate on.
/// </summary>
internal static class KeyRingPolicyChecks
{
    /// <summary>
    /// Refuses a rotation period that is not positive and a negative retention of a retired key.
    /// </summary>
    /// <remarks>
    /// A ring kept in memory would mint a key for every request with no positive period, and a negative retention
    /// drops a key while it still signs, so tokens it had signed stop verifying.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">A period is out of range.</exception>
    public static void EnsureRotatable(LocalKeys policy)
    {
        EnsurePositive(policy.RotateEvery, nameof(LocalKeys.RotateEvery), nameof(policy));
        EnsureNotNegative(policy.KeepRetiredFor, nameof(LocalKeys.KeepRetiredFor), nameof(policy));
    }

    /// <summary>
    /// Refuses a rotation period that is not positive and a negative retention of a retired key.
    /// </summary>
    /// <remarks>
    /// A minted ring divides time into rotation periods, so a period that is not positive divides by nothing, and a
    /// negative retention drops a key before its successor signs.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">A period is out of range.</exception>
    public static void EnsureRotatable(MintedKeys policy)
    {
        EnsurePositive(policy.RotateEvery, nameof(MintedKeys.RotateEvery), nameof(policy));
        if (policy.KeepRetiredFor is { } keepRetiredFor)
            EnsureNotNegative(keepRetiredFor, nameof(MintedKeys.KeepRetiredFor), nameof(policy));
    }

    /// <summary>
    /// Refuses a ring kept in memory whose retired key would leave before its successor is announced long enough to
    /// sign.
    /// </summary>
    /// <remarks>
    /// That ring counts the retention from the rotation, while the previous key keeps signing for the announcement
    /// window after it: a shorter retention drops the key still signing, and the new key signs before clients could
    /// have fetched it.
    /// </remarks>
    /// <param name="policy">The ring's policy.</param>
    /// <param name="propagation">How long a new key is announced before it signs.</param>
    /// <exception cref="ArgumentOutOfRangeException">The retention is shorter than the announcement.</exception>
    public static void EnsureRetainedThroughAnnouncement(LocalKeys policy, TimeSpan propagation)
    {
        if (!IsRetainedThroughAnnouncement(policy, propagation))
            throw new ArgumentOutOfRangeException(nameof(policy), policy.KeepRetiredFor, RetainedThroughAnnouncement);
    }

    /// <summary>
    /// Whether a ring kept in memory keeps a retired key at least as long as a new key is announced.
    /// </summary>
    public static bool IsRetainedThroughAnnouncement(LocalKeys policy, TimeSpan propagation)
        => policy.KeepRetiredFor >= propagation;

    /// <summary>
    /// Why a ring kept in memory refuses a retention shorter than the announcement of a new key.
    /// </summary>
    public const string RetainedThroughAnnouncement =
        $"{nameof(LocalKeys.KeepRetiredFor)} must be at least {nameof(KeyRingOptions.KeyRolloverPropagation)}, or " +
        "the key still signing leaves before its successor may sign.";

    private static void EnsurePositive(TimeSpan value, string name, string parameter)
    {
        if (value <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(parameter, value, $"{name} must be positive.");
    }

    private static void EnsureNotNegative(TimeSpan value, string name, string parameter)
    {
        if (value < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(parameter, value, $"{name} must not be negative.");
    }
}
