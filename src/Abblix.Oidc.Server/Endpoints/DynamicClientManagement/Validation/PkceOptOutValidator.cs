// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Refuses a registration turning PKCE off for a client the authorization endpoint holds to PKCE whatever it states.
/// </summary>
/// <remarks>
/// <see cref="ClientInfo.RequiresPkce"/> decides it, for the authorization endpoint and here alike. The refusal tells
/// the registrant at once, where an accepted <c>pkce_required</c> false would be stored, read back as true, and met
/// again only as a refused authorization request.
/// </remarks>
internal sealed class PkceOptOutValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error when the request states <c>pkce_required</c> false for a client
    /// that uses PKCE regardless, or <c>null</c> otherwise.
    /// </summary>
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        if (request.PkceRequired is false
            && ClientInfo.RequiresPkce(false, request.TokenEndpointAuthMethod, request.ApplicationType))
        {
            return ErrorFactory.InvalidClientMetadata(
                $"A native or public client uses PKCE: '{Parameters.PkceRequired}' must not be false");
        }

        return null;
    }
}
