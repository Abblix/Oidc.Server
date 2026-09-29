// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Fail-loud companion to the request-time profile enforcement: rejects a registration whose declared
/// response types can never satisfy the security profile the client falls under, so the contradiction
/// surfaces at registration with a clear <c>invalid_client_metadata</c> diagnostic instead of as a
/// per-request rejection the client has to reverse-engineer later. Whether a client is held to a
/// profile is a server-side policy decision: a dynamically registered client cannot declare one, so it
/// inherits the default profile of the issuer it registers with: <see cref="OidcOptions.DefaultSecurityProfile"/>
/// for a server without tenants, the tenant's own under multi-tenancy.
/// </summary>
/// <param name="issuerSettings">Provides the issuer's default profile a registered client inherits.</param>
public class SecurityProfileValidator(IIssuerSettings issuerSettings) : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error describing how the requested response types
    /// conflict with the server-wide security profile, or <c>null</c> when the registration is
    /// self-consistent (including when no profile applies).
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var violations = SecurityProfileConsistency.FindViolations(
            context.Request.ResponseTypes,
            context.Request.TokenEndpointAuthMethod,
            SecurityProfileRequirements.Resolve(issuerSettings.DefaultSecurityProfile));

        return violations.Count == 0
            ? null
            : ErrorFactory.InvalidClientMetadata(string.Join("; ", violations));
    }
}
