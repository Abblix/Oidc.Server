// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// The grant types the host lets new clients request start the host unless they refuse every registration: no limit,
/// or a set of named grant types, does; an empty set, or one holding a blank value, does not.
/// </summary>
public class NewClientGrantTypesValidatorTests
{
    public static TheoryData<string[]?, bool> Limits => new()
    {
        { null, true },
        { [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken], true },
        { [], false },
        { [GrantTypes.AuthorizationCode, " "], false },
        { [GrantTypes.AuthorizationCode, null!], false },
    };

    [Theory]
    [MemberData(nameof(Limits))]
    public void TheGrantTypesForNewClients_StartTheHostUnlessTheyRefuseEveryRegistration(string[]? allowed, bool starts)
    {
        var options = new OidcOptions { NewClientOptions = new NewClientOptions { AllowedGrantTypes = allowed } };

        var result = new NewClientGrantTypesValidator().Validate(name: null, options);

        Assert.Equal(starts, result.Succeeded);
    }
}
