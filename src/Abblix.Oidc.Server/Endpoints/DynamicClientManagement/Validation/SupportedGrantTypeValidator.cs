// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Rejects client registration when any value in <c>grant_types</c> is not advertised as
/// supported by this server, returning <c>invalid_client_metadata</c> per OIDC DCR §3.2.
/// Without this gate the registration would succeed and the client would only fail later at
/// the token endpoint with <c>unsupported_grant_type</c>, or at the authorization endpoint
/// for the <c>implicit</c> grant. Companion to <see cref="SupportedResponseTypeValidator"/>,
/// which applies the same rule to <c>response_types</c>.
/// </summary>
/// <param name="grantTypeInformers">All registered <see cref="IGrantTypeInformer"/>
/// contributors. Their union is the same <c>grant_types_supported</c> set the discovery
/// endpoint advertises, so registration gating, run-time gating, and discovery share one
/// source of truth. Notable contributors: the authorization endpoint yields
/// <c>implicit</c> only when the host has called <c>EnableImplicitFlow()</c>; the composite
/// token-endpoint grant handler yields every registered token-endpoint grant such as
/// <c>authorization_code</c>, <c>refresh_token</c>, <c>client_credentials</c>,
/// <c>jwt-bearer</c>, and <c>password</c> (only when <c>EnablePasswordGrant()</c> has been
/// called).</param>
public class SupportedGrantTypeValidator(
    IEnumerable<IGrantTypeInformer> grantTypeInformers)
    : SyncClientRegistrationContextValidator
{
    private readonly IReadOnlySet<string> _supportedGrantTypes = grantTypeInformers
        .SelectMany(gti => gti.GrantTypesSupported)
        .ToHashSet(StringComparer.Ordinal);

    /// <inheritdoc />
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var unsupported = context.Request.GrantTypes
            .Where(grantType => !_supportedGrantTypes.Contains(grantType))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (unsupported.Length == 0)
            return null;

        return ErrorFactory.InvalidClientMetadata(
            $"The following grant types are not supported by this server: {string.Join(", ", unsupported)}");
    }
}
