// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Reads a duration written as a whole number of seconds, the way protocol members such as <c>max_age</c> and
/// <c>expires_in</c> carry one.
/// </summary>
/// <remarks>
/// Every reader of such a member goes through here - JSON, a query string, a form - so one value is accepted or
/// refused the same way whichever way it arrived.
/// </remarks>
public static class Durations
{
    /// <summary>
    /// The duration of <paramref name="seconds"/>, or false when no duration is that long: a negative count, or one
    /// past what a <see cref="TimeSpan"/> holds.
    /// </summary>
    public static bool TryFromSeconds(long seconds, out TimeSpan duration)
    {
        if (seconds < 0 || seconds > (long)TimeSpan.MaxValue.TotalSeconds)
        {
            duration = default;
            return false;
        }

        duration = TimeSpan.FromSeconds(seconds);
        return true;
    }
}
