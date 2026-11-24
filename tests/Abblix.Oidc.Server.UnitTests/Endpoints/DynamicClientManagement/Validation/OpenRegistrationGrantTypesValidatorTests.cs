// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// While anybody may register and the host names no grant types, a client gets only those an end user takes part in;
/// a host requiring an initial access token, or naming the grant types itself, leaves the request to the other checks.
/// </summary>
public class OpenRegistrationGrantTypesValidatorTests
{
    private static async Task<string?> ValidateAsync(
        bool requireInitialAccessToken,
        string[]? allowedGrantTypes,
        string[] grantTypes,
        DynamicClientOperation operation = DynamicClientOperation.Register)
    {
        var options = new Mock<IOptionsMonitor<OidcOptions>>();
        options.Setup(monitor => monitor.CurrentValue).Returns(new OidcOptions
        {
            RequireInitialAccessToken = requireInitialAccessToken,
            NewClientOptions = new NewClientOptions { AllowedGrantTypes = allowedGrantTypes },
        });
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest { GrantTypes = grantTypes })
        {
            Operation = operation,
        };

        return (await new OpenRegistrationGrantTypesValidator(options.Object).ValidateAsync(SingleIssuer.Tenant, context))
            ?.Error;
    }

    [Fact]
    public async Task AGrantNoUserTakesPartIn_UnderOpenRegistrationWithoutAHostSet_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(false, null, [GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials]));

    [Fact]
    public async Task TheGrantsAUserTakesPartIn_UnderOpenRegistrationWithoutAHostSet_AreServed()
        => Assert.Null(await ValidateAsync(false, null, [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken]));

    /// <summary>
    /// An update replaces the metadata whole, so a client registered with the code grant cannot widen itself to a grant
    /// it would have been refused at registration.
    /// </summary>
    [Fact]
    public async Task AnUpdateToAGrantNoUserTakesPartIn_UnderOpenRegistration_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(false, null, [GrantTypes.ClientCredentials], DynamicClientOperation.Update));

    [Fact]
    public async Task AnyGrant_WhenAnInitialAccessTokenIsRequired_IsLeftToTheOtherChecks()
        => Assert.Null(await ValidateAsync(true, null, [GrantTypes.ClientCredentials]));

    [Fact]
    public async Task AnyGrant_WhenTheHostNamesTheGrantTypes_IsLeftToTheOtherChecks()
        => Assert.Null(await ValidateAsync(false, [GrantTypes.AuthorizationCode], [GrantTypes.ClientCredentials]));
}
