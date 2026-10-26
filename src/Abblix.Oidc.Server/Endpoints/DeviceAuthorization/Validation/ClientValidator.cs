// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// Validates the client in a device authorization request.
/// </summary>
/// <param name="clientAuthenticator">The service used to authenticate clients.</param>
/// <param name="tenantAccessor">Names the tenant the request is served at.</param>
public class ClientValidator(IClientAuthenticator clientAuthenticator, ITenantAccessor tenantAccessor)
    : IDeviceAuthorizationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(DeviceAuthorizationValidationContext context)
    {
        var clientInfo = await clientAuthenticator.TryAuthenticateClientAsync(
            tenantAccessor.CurrentTenant(), context.ClientRequest);
        if (clientInfo == null)
        {
            return new OidcError(
                ErrorCodes.UnauthorizedClient,
                "The client is not authorized");
        }

        if (!clientInfo.EffectiveGrantTypes.Contains(GrantTypes.DeviceAuthorization))
        {
            return new OidcError(
                ErrorCodes.UnauthorizedClient,
                "The client is not authorized to use the device authorization grant");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
