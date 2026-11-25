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
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Holds a client nobody vetted, one registering while anybody may register or updating a registration made so, to
/// what the host names in
/// <see cref="NewClientOptions"/>, and where it names nothing, to the least: the grant types of an interactive sign-in,
/// the authorization code and the refresh token, and no resource to get an access token for.
/// </summary>
/// <remarks>
/// Registration is open as <see cref="OpenRegistration.AdmitsAnyRegistrant"/> answers it, the answer the trust a
/// registered client is created with is read from too: no initial access token is asked, and no software statement from
/// an issuer the host trusts. A grant no end user approves, such as client credentials, would then give whoever
/// registered tokens of its own, as a client allowed every resource would get tokens for every API the tenant
/// protects. It judges the request after a trusted software statement has replaced the metadata it carries, so a
/// statement adds no grant or resource the defaults hold back. A set the host names is held by
/// <see cref="HostGrantedMetadataValidator"/> instead, so a request is judged by one set alone. It is in
/// <see cref="ClientRegistrationMetadataChecks.Registration"/> alone: a client resolved from its metadata document is
/// held to <see cref="ClientIdMetadataDocumentOptions.AllowedGrantTypes"/>, which this would narrow. An update is
/// judged by the client it replaces rather than by the settings: a client registered while registration was open is
/// <see cref="ClientTrust.Unreviewed"/> for good, so it cannot widen itself once registration closes, and one let in
/// while it was closed keeps what it was given once it opens. The settings are read at each request.
/// </remarks>
/// <param name="options">The server options carrying the settings.</param>
internal sealed class OpenRegistrationDefaultsValidator(IOptionsMonitor<OidcOptions> options)
    : SyncClientRegistrationContextValidator
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        var settings = options.CurrentValue;
        if (!IsUnreviewed(context, settings))
            return null;

        var granted = settings.NewClientOptions;

        // Written here rather than left to the builder, whose options are a snapshot taken at startup; a client naming
        // resources is judged against the host's set instead
        if (context.Request.AllowedResources is null)
            context.Request = context.Request with { AllowedResources = granted.UnreviewedClientResources };

        if (granted.AllowedGrantTypes is not null)
            return null;

        return HostGrantedMetadataValidator.WithinAllowedGrantTypes(
            context.Request.GrantTypes,
            NewClientOptions.InteractiveSignInGrantTypes);
    }

    /// <summary>
    /// Whether the client the request registers or replaces is one nobody vetted: a registration while anybody may
    /// register, which is what its stored trust is decided by, or an update of a client stored as unreviewed.
    /// </summary>
    private static bool IsUnreviewed(ClientRegistrationValidationContext context, OidcOptions settings)
        => context.Operation switch
        {
            DynamicClientOperation.Register => OpenRegistration.AdmitsAnyRegistrant(settings),
            DynamicClientOperation.Update => StoredTrustOf(context) switch
            {
                ClientTrust.Unreviewed => true,
                ClientTrust.Reviewed => false,
                var trust => throw new InvalidOperationException($"Unknown {nameof(ClientTrust)} value {trust}"),
            },
            _ => throw new InvalidOperationException($"Unsupported dynamic client operation: {context.Operation}"),
        };

    private static ClientTrust StoredTrustOf(ClientRegistrationValidationContext context)
        => (context.StoredClient ?? throw new InvalidOperationException(
            $"An update is judged without the {nameof(context.StoredClient)} it replaces")).Trust;
}
