// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// A device authorization request asking for offline_access is refused only for a client whose offline access is
/// disabled: the end user approves the request on the device, so a client that may receive offline access with
/// prompt=consent receives it here too.
/// </summary>
public class ScopeValidatorTests
{
    private delegate bool TryGetCallback(TenantDefinition tenant, string scope, out ScopeDefinition? definition);

    [Theory]
    [InlineData(OfflineAccess.Disabled, ErrorCodes.InvalidScope)]
    [InlineData(OfflineAccess.ConsentRequired, null)]
    [InlineData(OfflineAccess.Allowed, null)]
    public async Task ValidateAsync_OfflineAccess_IsRefusedOnlyWhenDisabled(OfflineAccess offlineAccess, string? error)
    {
        var scopeManager = new Mock<IScopeManager>();
        scopeManager
            .Setup(m => m.TryGet(TestTenant.Matched, It.IsAny<string>(), out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = new ScopeDefinition(scope);
                return true;
            }));
        var validator = new ScopeValidator(scopeManager.Object, tenantAccessor: SingleIssuer.Accessor);
        var context = new DeviceAuthorizationValidationContext(
            new DeviceAuthorizationRequest { Scope = [Scopes.OpenId, Scopes.OfflineAccess] },
            new ClientRequest { ClientId = "device-client" })
        {
            ClientInfo = new ClientInfo("device-client") { OfflineAccess = offlineAccess },
        };

        var result = await validator.ValidateAsync(context);

        Assert.Equal(error, result?.Error);
    }
}
