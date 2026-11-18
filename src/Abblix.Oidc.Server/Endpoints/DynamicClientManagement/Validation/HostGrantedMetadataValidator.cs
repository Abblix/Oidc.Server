// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;
using Parameters = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Holds the registration members that say what a client may reach, its allowed resources and its token exchange
/// audiences, to the sets the host grants in <see cref="NewClientOptions"/>: a client may narrow them, never widen
/// them, so the limit on a client is never set by the client it limits.
/// </summary>
/// <param name="options">The server options carrying the host's sets.</param>
public class HostGrantedMetadataValidator(IOptionsMonitor<OidcOptions> options) : SyncClientRegistrationContextValidator
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        var granted = options.CurrentValue.NewClientOptions;
        var request = context.Request;

        return WithinGranted(request.AllowedResources, granted.AllowedResources, Parameters.AllowedResources)
               ?? WithinGranted(
                   request.TokenExchangeAudiences,
                   granted.TokenExchangeAudiences,
                   Parameters.TokenExchangeAudiences)
               ?? WithinAllowedGrantTypes(request.GrantTypes, granted.AllowedGrantTypes);
    }

    /// <summary>
    /// The refusal of a grant type in <paramref name="requested"/> outside <paramref name="allowed"/>, or null, which
    /// it also is when the host sets no limit.
    /// </summary>
    /// <remarks>
    /// Refused rather than replaced, though RFC 7591 section 2 permits either: section 5 names
    /// <c>invalid_client_metadata</c> as the answer of a server that disallows a grant type, and dropping one would
    /// leave the response types that need it registered without it, the inconsistent state section 2.1 asks the
    /// server to keep a client out of.
    /// </remarks>
    private static OidcError? WithinAllowedGrantTypes(string[] requested, string[]? allowed)
    {
        if (allowed is null)
            return null;

        var outside = requested.Where(grantType => !allowed.Contains(grantType, StringComparer.Ordinal)).ToArray();
        return outside.Length > 0
            ? ErrorFactory.InvalidClientMetadata(
                $"The server does not grant the {Parameters.GrantTypes} value {outside[0] ?? "null"}")
            : null;
    }

    /// <summary>
    /// The refusal of a value of <paramref name="sent"/> outside <paramref name="granted"/>, or null.
    /// </summary>
    private static OidcError? WithinGranted<T>(T[]? sent, T[]? granted, string member)
    {
        // Every value is read, one naming nothing included, which the host's set does not hold either
        var outside = (sent ?? []).Where(value => granted is null || !granted.Contains(value)).ToArray();
        return outside.Length > 0
            ? ErrorFactory.InvalidClientMetadata(
                $"The server does not grant the {member} value {outside[0]?.ToString() ?? "null"}")
            : null;
    }
}
