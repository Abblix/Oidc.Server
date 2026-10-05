// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Xunit;
using WireRequest = Abblix.Oidc.Server.Model.DeviceAuthorizationRequest;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DeviceAuthorization;

public class ValidDeviceAuthorizationRequestTests
{
    /// <summary>
    /// A scope only a requested resource declares is kept with the scopes of the request, so the host approving
    /// the user code and the token it leads to both carry it, as on the other endpoints.
    /// </summary>
    [Fact]
    public void AScopeOfARequestedResource_IsKeptWithTheScopes()
    {
        const string resourceScope = "orders.read";
        var context = new DeviceAuthorizationValidationContext(new WireRequest(), new ClientRequest())
        {
            ClientInfo = new ClientInfo("device_client"),
            Scope = [new ScopeDefinition(Scopes.OpenId)],
            Resources = [new ResourceDefinition(new Uri("https://orders.example.com"), new ScopeDefinition(resourceScope))],
        };

        var valid = new ValidDeviceAuthorizationRequest(context);

        Assert.Equal([Scopes.OpenId, resourceScope], valid.Scope);
    }
}
