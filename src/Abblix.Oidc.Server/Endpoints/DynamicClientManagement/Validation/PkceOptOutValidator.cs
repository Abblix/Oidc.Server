// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Refuses a registration turning PKCE off for a native app or for a client with no credentials.
/// </summary>
/// <remarks>
/// RFC 8252 section 8.1: "Authorization servers SHOULD reject authorization requests from native apps that don't use
/// PKCE", and RFC 9700 section 2.1.1: "Public clients MUST use PKCE". A registration stating <c>pkce_required</c>
/// false would turn that refusal off for the client it registers, so it is refused where the client asks.
/// </remarks>
internal sealed class PkceOptOutValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error when a native or public client states <c>pkce_required</c>
    /// false, or <c>null</c> otherwise.
    /// </summary>
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        if (request.PkceRequired is not false)
            return null;

        if (request.ApplicationType == ApplicationTypes.Native)
        {
            return ErrorFactory.InvalidClientMetadata(
                $"A native client uses PKCE: '{Parameters.PkceRequired}' must not be false (RFC 8252 section 8.1)");
        }

        if (request.TokenEndpointAuthMethod == ClientAuthenticationMethods.None)
        {
            return ErrorFactory.InvalidClientMetadata(
                $"A public client uses PKCE: '{Parameters.PkceRequired}' must not be false "
                + "(RFC 9700 section 2.1.1)");
        }

        return null;
    }
}
