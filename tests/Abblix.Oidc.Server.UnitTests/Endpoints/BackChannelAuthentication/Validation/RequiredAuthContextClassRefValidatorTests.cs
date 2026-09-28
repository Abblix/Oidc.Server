// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// A decoupled request's essential <c>acr</c> is read when the request arrives: a malformed one is refused
/// there, and a well-formed one reaches the host as the levels it has to authenticate at.
/// </summary>
public class RequiredAuthContextClassRefValidatorTests
{
    private const string Level = "urn:example:acr:strong";

    /// <summary>
    /// A qualifier that is not a string names a level nobody can hold, so the request is refused before any
    /// end user is disturbed on a device, the way the authorization endpoint refuses it.
    /// </summary>
    [Fact]
    public async Task AMalformedEssentialAcr_IsRefusedAsAnInvalidRequest()
    {
        var context = ContextRequiring(new RequestedClaimDetails { Essential = true, Values = [42] });

        var error = await new RequiredAuthContextClassRefValidator().ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// A well-formed essential <c>acr</c> is accepted, and the host initiating the authentication receives
    /// the levels it has to meet rather than having to read the <c>claims</c> parameter itself.
    /// </summary>
    [Fact]
    public async Task AWellFormedEssentialAcr_ReachesTheHostAsTheRequiredLevels()
    {
        var context = ContextRequiring(new RequestedClaimDetails { Essential = true, Values = [Level] });

        var error = await new RequiredAuthContextClassRefValidator().ValidateAsync(context);

        Assert.Null(error);
        Assert.Equal([Level], Assert.IsType<string[]>(new ValidBackChannelAuthenticationRequest(context).RequiredAuthContextClassRefs));
    }

    /// <summary>
    /// A voluntary <c>acr</c> requires nothing, and the host is told so by the absence of any level.
    /// </summary>
    [Fact]
    public async Task AVoluntaryAcr_RequiresNoLevel()
    {
        var context = ContextRequiring(new RequestedClaimDetails { Values = [Level] });

        var error = await new RequiredAuthContextClassRefValidator().ValidateAsync(context);

        Assert.Null(error);
        Assert.Null(new ValidBackChannelAuthenticationRequest(context).RequiredAuthContextClassRefs);
    }

    private static BackChannelAuthenticationValidationContext ContextRequiring(RequestedClaimDetails acr)
    {
        var request = new BackChannelAuthenticationRequest
        {
            Claims = new RequestedClaims { IdToken = new() { [IanaClaimTypes.Acr] = acr } },
        };

        return new BackChannelAuthenticationValidationContext(request, new ClientRequest())
        {
            ClientInfo = new ClientInfo("test-client"),
        };
    }
}
