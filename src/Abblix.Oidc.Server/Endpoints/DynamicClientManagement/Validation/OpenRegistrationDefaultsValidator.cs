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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Holds a client that registers or updates itself while anybody may register to what the host names in
/// <see cref="NewClientOptions"/>, and where it names nothing, to the least: the grant types an end user takes part
/// in, the authorization code and the refresh token, and no resource to get an access token for.
/// </summary>
/// <remarks>
/// While <see cref="OidcOptions.RequireInitialAccessToken"/> is <c>false</c> anybody may register, and a grant no end
/// user approves, such as client credentials, would give whoever registered tokens of its own, as a client allowed
/// every resource would get tokens for every API the tenant protects. A set the host names is held by
/// <see cref="HostGrantedMetadataValidator"/> instead, so a request is judged by one set alone. A request check rather
/// than a metadata one: a client resolved from its metadata document is held to
/// <see cref="ClientIdMetadataDocumentOptions.AllowedGrantTypes"/>, which this would narrow. An update is judged as a
/// registration is, since it replaces the metadata whole. Both settings are read at each request.
/// </remarks>
/// <param name="options">The server options carrying the settings.</param>
internal sealed class OpenRegistrationDefaultsValidator(IOptionsMonitor<OidcOptions> options)
    : SyncClientRegistrationContextValidator
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        var settings = options.CurrentValue;
        if (settings.RequireInitialAccessToken)
            return null;

        var granted = settings.NewClientOptions;

        // A client naming resources is judged against the host's set, so only one naming none is given the empty list
        if (granted.AllowedResources is null && context.Request.AllowedResources is null)
            context.Request = context.Request with { AllowedResources = [] };

        if (granted.AllowedGrantTypes is not null)
            return null;

        return HostGrantedMetadataValidator.WithinAllowedGrantTypes(
            context.Request.GrantTypes,
            NewClientOptions.UserGrantTypes);
    }
}
