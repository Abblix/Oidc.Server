// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// FAPI 1.0 Part 1 section 5.2.2.3, which Part 2 section 5.2.2 takes in: "If the client does not requests the openid
/// scope, the authorization server shall require the state parameter defined in Section 4.1.1 of RFC6749".
/// </summary>
public class StateValidatorTests
{
    private static AuthorizationValidationContext Context(
        ClientSecurityProfile? profile, string scope, string? state) => new(new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [scope],
            State = state,
        })
    {
        ClientInfo = new ClientInfo(TestConstants.DefaultClientId)
        {
            SecurityProfile = profile,
            AllowedScopes = [scope],
        },
    };

    /// <summary>
    /// A client held to FAPI 1.0 Advanced naming no openid scope is refused a request without state; with state, or
    /// with the openid scope, or held to no profile, it passes.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, Scopes.Profile, null, ErrorCodes.InvalidRequest)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, Scopes.Profile, "state-1", null)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, Scopes.OpenId, null, null)]
    [InlineData(null, Scopes.Profile, null, null)]
    public async Task ValidateAsync_RequiresStateWithoutTheOpenIdScope(
        ClientSecurityProfile? profile, string scope, string? state, string? expectedError)
    {
        var result = await new StateValidator().ValidateAsync(SingleIssuer.Tenant, Context(profile, scope, state));

        Assert.Equal(expectedError, result?.Error);
    }
}
