// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A retention at which the record of a session's clients expires as it is written is refused at startup, since
/// every logout would then notify nobody and nothing would say so.
/// </summary>
public class SessionClientsRetentionOptionsValidatorTests
{
    private static bool Fails(TimeSpan retention)
        => new SessionClientsRetentionOptionsValidator()
            .Validate(null, new OidcOptions { SessionClientsRetention = retention })
            .Failed;

    [Fact]
    public void The_default_retention_is_accepted()
    {
        Assert.False(new SessionClientsRetentionOptionsValidator().Validate(null, new OidcOptions()).Failed);
    }

    [Fact]
    public void The_shortest_positive_retention_is_accepted()
    {
        Assert.False(Fails(TimeSpan.FromTicks(1)));
    }

    [Fact]
    public void A_retention_of_zero_is_refused()
    {
        Assert.True(Fails(TimeSpan.Zero));
    }

    [Fact]
    public void A_negative_retention_is_refused()
    {
        Assert.True(Fails(TimeSpan.FromDays(-1)));
    }
}
