// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A configuration still naming the obsolete <see cref="JwtBearerOptions.StrictAudienceValidation"/> binds as before,
/// the setting and the ones beside it alike, so a deployment carrying it keeps starting.
/// </summary>
public class JwtBearerOptionsBindingTests
{
    [Fact]
    public void AConfigurationNamingStrictAudienceValidation_StillBinds()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["JwtBearer:StrictAudienceValidation"] = "false",
                ["JwtBearer:MaxJwtSize"] = "4096",
            })
            .Build();

        var options = configuration.GetSection("JwtBearer").Get<JwtBearerOptions>();

        Assert.NotNull(options);
        // The binding of the obsolete setting is what is checked here, so reading it is not a warning
#pragma warning disable CS0618
        Assert.False(options.StrictAudienceValidation);
#pragma warning restore CS0618
        Assert.Equal(4096, options.MaxJwtSize);
    }
}
