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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Refuses a registration or an update giving a client that authenticates with <c>none</c> a grant type kept for
/// confidential clients (<see cref="ConfidentialGrantTypes"/>), such as client credentials, which RFC 6749 section 4.4
/// says "MUST only be used by confidential clients".
/// </summary>
internal sealed class ConfidentialGrantTypeValidator : SyncClientRegistrationContextValidator
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        var refused = ConfidentialGrantTypes.RefusedTo(request.TokenEndpointAuthMethod, request.GrantTypes);
        if (refused.Length == 0)
            return null;

        return ErrorFactory.InvalidClientMetadata(
            $"The grant types {string.Join(", ", refused)} are only for a client that authenticates itself, and " +
            $"'{request.TokenEndpointAuthMethod}' does not");
    }
}
