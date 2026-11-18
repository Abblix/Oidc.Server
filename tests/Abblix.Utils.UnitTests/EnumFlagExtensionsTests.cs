// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils.UnitTests;

/// <summary>
/// An enum value left at zero reads as the default its caller names, and any value written stays as written.
/// </summary>
public class EnumFlagExtensionsTests
{
    [Flags]
    public enum Permits
    {
        First = 1 << 0,
        Second = 1 << 1,
    }

    [Theory]
    [InlineData((Permits)0, Permits.First)]
    [InlineData(Permits.First, Permits.First)]
    [InlineData(Permits.Second, Permits.Second)]
    [InlineData(Permits.First | Permits.Second, Permits.First | Permits.Second)]
    public void ByDefault_ReplacesZeroAlone(Permits written, Permits read)
        => Assert.Equal(read, written.ByDefault(Permits.First));
}
