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
/// The grant types of new clients and of document clients bound from configuration are taken as written: the binder
/// adds to a list already there, so both are unset until a host names them, and a host may name fewer than the grants
/// of a sign-in.
/// </summary>
public class GrantTypeListsBindingTests
{
    [Fact]
    public void ConfiguredLists_AreTakenAsWritten()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Oidc:NewClientOptions:AllowedGrantTypes:0"] = GrantTypes.AuthorizationCode,
                ["Oidc:ClientIdMetadataDocuments:AllowedGrantTypes:0"] = GrantTypes.AuthorizationCode,
            })
            .Build();
        var options = new OidcOptions();

        configuration.GetSection("Oidc").Bind(options);

        Assert.Equal([GrantTypes.AuthorizationCode], options.NewClientOptions.AllowedGrantTypes!);
        Assert.Equal([GrantTypes.AuthorizationCode], options.ClientIdMetadataDocuments.AllowedGrantTypes!);
    }
}
