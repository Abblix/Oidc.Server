// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// The offline access the host grants new clients starts the host only when the enumeration defines it.
/// </summary>
public class NewClientOfflineAccessValidatorTests
{
    [Theory]
    [InlineData(OfflineAccess.Disabled, true)]
    [InlineData(OfflineAccess.ConsentRequired, true)]
    [InlineData(OfflineAccess.Allowed, true)]
    [InlineData((OfflineAccess)7, false)]
    public void TheOfflineAccessForNewClients_StartsTheHostOnlyWhenDefined(OfflineAccess granted, bool starts)
    {
        var options = new OidcOptions { NewClientOptions = new NewClientOptions { OfflineAccess = granted } };

        var result = new NewClientOfflineAccessValidator().Validate(name: null, options);

        Assert.Equal(starts, result.Succeeded);
    }

    [Fact]
    public void TheOfflineAccessForNewClients_RequiresConsentPromptByDefault()
        => Assert.Equal(OfflineAccess.ConsentRequired, new NewClientOptions().OfflineAccess);
}
