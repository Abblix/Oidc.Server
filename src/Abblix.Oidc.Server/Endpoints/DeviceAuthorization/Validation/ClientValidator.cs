// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Validation;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// Validates the client in a device authorization request.
/// </summary>
/// <param name="clientAuthenticator">The service used to authenticate clients.</param>
/// <param name="clientInfoProvider">The client store, asked through a lookup made for each request.</param>
public class ClientValidator(IClientAuthenticator clientAuthenticator, IClientInfoProvider clientInfoProvider)
    : IDeviceAuthorizationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(TenantDefinition tenant, DeviceAuthorizationValidationContext context)
    {
        // RFC 8628 section 3.2 answers an error the way the token endpoint does, and RFC 6749 section 5.2 names a
        // request that "includes multiple credentials, utilizes more than one mechanism for authenticating the
        // client" an invalid_request. Decided before the authenticator, which would count a failed attempt
        if (context.ClientRequest.HasMoreThanOneAuthorizationHeader)
            return ErrorFactory.MoreThanOneAuthorizationHeader;

        var clients = new RequestScopedClientInfoProvider(clientInfoProvider);
        var authenticated = await clientAuthenticator.TryAuthenticateClientAsync(tenant, context.ClientRequest, clients);
        if (!authenticated.TryGetSuccess(out var clientInfo))
        {
            // RFC 6749 section 5.2 names a request that "utilizes more than one mechanism for authenticating the
            // client" an invalid_request, not a failed authentication
            if (authenticated.GetFailure() is MoreThanOneClientAuthenticationMethodError moreThanOneMethod)
                return moreThanOneMethod;

            // RFC 8628 section 3.2 answers an error the way the token endpoint does, and RFC 6749 section 5.2 names
            // a failed client authentication invalid_client.
            return BasicChallenge.InvalidClient(context.ClientRequest, "The client is not authorized");
        }

        if (!clientInfo.MayUseGrantType(GrantTypes.DeviceAuthorization))
        {
            return new OidcError(
                ErrorCodes.UnauthorizedClient,
                "The client is not authorized to use the device authorization grant");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
