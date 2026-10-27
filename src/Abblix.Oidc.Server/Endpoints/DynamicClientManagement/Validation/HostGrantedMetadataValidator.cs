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
                   Parameters.TokenExchangeAudiences);
    }

    /// <summary>
    /// The refusal of a value of <paramref name="sent"/> outside <paramref name="granted"/>, or null.
    /// </summary>
    private static OidcError? WithinGranted<T>(T[]? sent, T[]? granted, string member)
    {
        var outside = (sent ?? []).FirstOrDefault(value => granted is null || !granted.Contains(value));
        return outside is not null
            ? ErrorFactory.InvalidClientMetadata($"The server does not grant the {member} value {outside}")
            : null;
    }
}
