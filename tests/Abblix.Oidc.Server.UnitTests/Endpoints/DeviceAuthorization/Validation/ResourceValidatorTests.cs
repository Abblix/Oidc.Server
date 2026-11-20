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
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// The resources a device authorization request is settled with.
/// </summary>
public class ResourceValidatorTests
{
    /// <summary>
    /// An offline_access the client may not receive a refresh token for is ignored before the resources are settled,
    /// so a resource declaring it does not keep it among the scopes the request is served with.
    /// </summary>
    [Fact]
    public async Task AnIgnoredOfflineAccess_IsNotKeptOnAResourceDeclaringIt()
    {
        var resource = new Uri("https://orders.example.com");
        var tenant = new TestIssuer
        {
            Resources =
            [
                new ResourceDefinition(
                    resource, new ScopeDefinition("orders.read"), new ScopeDefinition(Scopes.OfflineAccess)),
            ],
        }.ToTenant();
        var context = new DeviceAuthorizationValidationContext(
            new DeviceAuthorizationRequest { Scope = ["orders.read", Scopes.OfflineAccess], Resources = [resource] },
            new ClientRequest { ClientId = "device-client" })
        {
            ClientInfo = new ClientInfo("device-client")
            {
                AllowedScopes = ["orders.read", Scopes.OfflineAccess],
                AllowedGrantTypes = [GrantTypes.DeviceAuthorization],
            },
        };

        var result = await new ResourceValidator(SingleIssuer.ResourceManager()).ValidateAsync(tenant, context);

        Assert.Null(result);
        Assert.Equal("orders.read", Assert.Single(Assert.Single(context.Resources).Scopes).Scope);
    }
}
