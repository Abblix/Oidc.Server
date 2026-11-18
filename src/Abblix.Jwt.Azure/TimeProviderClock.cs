// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Internal;

namespace Abblix.Jwt.Azure;

/// <summary>
/// The clock a <see cref="Microsoft.Extensions.Caching.Memory.MemoryCache"/> reads, taken from a
/// <see cref="TimeProvider"/>, so the cached crypto clients age by the same clock as the rest of the host.
/// </summary>
/// <param name="timeProvider">The clock to read.</param>
internal sealed class TimeProviderClock(TimeProvider timeProvider) : ISystemClock
{
    /// <inheritdoc />
    public DateTimeOffset UtcNow => timeProvider.GetUtcNow();
}
