// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Pins the display values OpenID Connect Core 1.0, section 3.1.2.1, defines as accepted, and any other refused as an
/// invalid request.
/// </summary>
public class DisplayValidatorTests
{
    private static AuthorizationValidationContext ContextWith(string? display) => new(new AuthorizationRequest
    {
        ClientId = TestConstants.DefaultClientId,
        ResponseType = [ResponseTypes.Code],
        RedirectUri = TestConstants.DefaultRedirectUri,
        Scope = [Scopes.OpenId],
        Display = display,
    })
    {
        ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        ResponseMode = ResponseModes.Query,
    };

    [Theory]
    [InlineData(null)]
    [InlineData(DisplayModes.Page)]
    [InlineData(DisplayModes.Popup)]
    [InlineData(DisplayModes.Touch)]
    [InlineData(DisplayModes.Wap)]
    public async Task ADefinedDisplay_IsAccepted(string? display)
        => Assert.Null(await new DisplayValidator().ValidateAsync(ContextWith(display)));

    [Theory]
    [InlineData("hologram")]
    [InlineData("Page")]
    public async Task AnyOtherDisplay_IsRefusedAsAnInvalidRequest(string display)
    {
        var error = await new DisplayValidator().ValidateAsync(ContextWith(display));

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }
}
