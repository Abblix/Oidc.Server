// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the <c>offline_access</c> registration parameter, a server extension to RFC 7591 metadata: a client
/// registering itself may ask for no offline access or for offline access with <c>prompt=consent</c>, but not for
/// offline access without it.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0, section 11, waives <c>prompt=consent</c> only where "other conditions for processing the
/// request permitting offline access" are in place, and stating those conditions for a client is the host's call,
/// never the client's own. An update (RFC 7592 section 2.2) sends back the metadata the server returned, so a client
/// the host already allowed keeps <c>allowed</c> there, while one it did not cannot raise itself to it.
/// </remarks>
/// <param name="clientInfoProvider">Store consulted for the offline access of the client being updated.</param>
/// <param name="tenantAccessor">Names the tenant the request is served at.</param>
public class OfflineAccessValidator(IClientInfoProvider clientInfoProvider, ITenantAccessor tenantAccessor) : IClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error when the client asks for offline access without
    /// <c>prompt=consent</c> it does not already have, or names no offline access at all; <c>null</c> otherwise.
    /// </summary>
    public async Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
    {
        switch (context.Request.OfflineAccess)
        {
            case OfflineAccess.Disabled or OfflineAccess.ConsentRequired:
                return null;

            case OfflineAccess.Allowed:
                if (await AlreadyAllowedAsync(context))
                    return null;

                return ErrorFactory.InvalidClientMetadata(
                    $"The {Parameters.OfflineAccess} a client asks for at registration requires prompt=consent");

            // A number, or a list of names, that reads into none of the named values
            default:
                return ErrorFactory.InvalidClientMetadata($"The {Parameters.OfflineAccess} value is not recognized");
        }
    }

    /// <summary>
    /// Whether the request updates a client the host has already allowed offline access without
    /// <c>prompt=consent</c>.
    /// </summary>
    private async Task<bool> AlreadyAllowedAsync(ClientRegistrationValidationContext context)
    {
        switch (context.Operation)
        {
            case DynamicClientOperation.Register:
                return false;

            case DynamicClientOperation.Update:
                var clientId = context.Request.ClientId;
                return clientId.HasValue() &&
                       await clientInfoProvider.TryFindClientAsync(tenantAccessor.CurrentTenant(), clientId) is { OfflineAccess: OfflineAccess.Allowed };

            default:
                throw new InvalidOperationException($"Unsupported dynamic client operation: {context.Operation}");
        }
    }
}
