// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Microsoft.Extensions.Internal;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Lets an in-memory cache expire its entries on the same clock a test advances.
/// </summary>
/// <remarks>
/// Without it the cache ages entries on the real clock while the code under test reads a fake one, so
/// advancing the fake clock expires nothing and every lifetime passed to the store goes unexercised.
/// </remarks>
internal sealed class StoreClock(TimeProvider time) : ISystemClock
{
    public DateTimeOffset UtcNow => time.GetUtcNow();
}
