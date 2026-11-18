// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// Finds a client the store does not know by the metadata document its identifier names
/// (draft-ietf-oauth-client-id-metadata-document), so every place the server looks a client up - the authorization,
/// token and pushed authorization endpoints, client authentication, logout - finds such a client as it finds a stored
/// one (Decorator).
/// </summary>
/// <remarks>
/// The store is asked first, so a client the host configured or registered under a URL keeps its configuration:
/// section 9.2 has the server "MAY pre-register Client Identifier URLs", and a pre-registered client is then fetched
/// from nowhere. A document is held by its URL, once for every tenant, while what it makes of the client is decided at
/// each tenant, since the tenant's scopes, resources and security profile judge it.
/// </remarks>
/// <param name="inner">The client store.</param>
/// <param name="logger">Records why an identifier was not resolved.</param>
/// <param name="documents">The documents fetched and held.</param>
/// <param name="scopes">Opens the container a document is judged in, since the checks it passes are scoped services.
/// </param>
/// <param name="options">The host's settings, read on each lookup.</param>
internal sealed partial class ClientIdMetadataDocumentClients(
    IClientInfoProvider inner,
    ILogger<ClientIdMetadataDocumentClients> logger,
    HeldMetadataDocuments documents,
    IServiceScopeFactory scopes,
    IOptionsMonitor<OidcOptions> options) : IClientInfoProvider
{
    /// <inheritdoc />
    public async Task<ClientInfo?> TryFindClientAsync(TenantDefinition tenant, string clientId)
    {
        var stored = await inner.TryFindClientAsync(tenant, clientId);
        if (stored is not null)
            return stored;

        var settings = options.CurrentValue;
        var url = Fetched(tenant, clientId, settings);
        if (url is null)
            return null;

        var held = await documents.GetAsync(clientId, url);
        if (held is null)
            return null;

        var generation = (tenant.Id, tenant.Generation);
        if (held.Clients.TryGetValue(generation, out var client))
            return client;

        client = await JudgeAsync(tenant, clientId, held.Metadata, settings.NewClientOptions);

        // A refusal is not kept: section 6.2 has the server "MUST NOT cache documents which are invalid", and one is so
        // at this tenant
        return client is null ? null : held.Clients.GetOrAdd(generation, client);
    }

    /// <summary>
    /// The URL to fetch <paramref name="clientId"/>'s document from, or null when it is not fetched.
    /// </summary>
    private Uri? Fetched(TenantDefinition tenant, string clientId, OidcOptions settings)
    {
        var why = ClientIdentifierUrl.WhyNotFetched(clientId, out var url);
        if (why is not null)
        {
            // An identifier that is no URL at all is an unknown client like any other, and says nothing worth a line
            if (clientId.StartsWith(Uri.UriSchemeHttps + Uri.SchemeDelimiter, StringComparison.Ordinal))
                LogIdentifierNotFetched(clientId, why);

            return null;
        }

        if (!ClientIdentifierUrl.IsAllowed(clientId, settings.ClientIdMetadataDocuments.AllowedClientIdPrefixes))
        {
            LogIdentifierNotAllowed(clientId);
            return null;
        }

        if (NamesAServer(tenant, clientId, settings))
        {
            LogIdentifierNamesAServer(clientId, tenant.Id);
            return null;
        }

        return url;
    }

    /// <summary>
    /// Whether <paramref name="clientId"/> is the identifier of a server this one issues for or trusts.
    /// </summary>
    /// <remarks>
    /// Section 10.1: the server "SHOULD reject a Client Identifier URL that is equal, using simple string comparison
    /// ..., to its own issuer identifier, or to the identifier of any authorization server or resource server it has a
    /// trust relationship with", since the identifier then reads in a token or an assertion as that party's. Those are
    /// the tenant's issuer, the resources it issues tokens for and the issuers whose assertions the JWT bearer grant
    /// accepts.
    /// </remarks>
    private static bool NamesAServer(TenantDefinition tenant, string clientId, OidcOptions settings)
    {
        IEnumerable<string> servers =
        [
            tenant.Issuer.OriginalString,
            tenant.Issuer.AbsoluteUri,
            ..(tenant.Resources ?? []).SelectMany(resource =>
                new[] { resource.Resource.OriginalString, resource.Resource.AbsoluteUri }),
            ..settings.JwtBearer.TrustedIssuers.Select(issuer => issuer.Issuer),
        ];

        return servers.Contains(clientId, StringComparer.Ordinal);
    }

    /// <summary>
    /// The client <paramref name="metadata"/> describes at <paramref name="tenant"/>, or null when the tenant refuses
    /// it.
    /// </summary>
    private async Task<ClientInfo?> JudgeAsync(
        TenantDefinition tenant,
        string clientId,
        ClientRegistrationRequest metadata,
        NewClientOptions newClientOptions)
    {
        await using var scope = scopes.CreateAsyncScope();
        var validator = ActivatorUtilities.CreateInstance<ClientIdMetadataDocumentValidator>(scope.ServiceProvider);

        // A copy, since a check may complete the metadata it judges and the document is shared by every tenant
        var judged = await validator.ValidateAsync(tenant, metadata with { });
        if (!judged.TryGetSuccess(out var context))
        {
            LogClientRefused(clientId, tenant.Id, judged.GetFailure().ErrorDescription);
            return null;
        }

        // Built as a newly registered client is, with the host's defaults for what the metadata leaves unnamed. No
        // secret: section 4.1 leaves a document none
        return new ClientInfoBuilder(clientId, context.Request)
            .WithSectorIdentifier(context.SectorIdentifier)
            .WithDefaultScope(newClientOptions.Scope)
            .WithDefaultOfflineAccess(newClientOptions.OfflineAccess)
            .WithDefaultAllowedResources(newClientOptions.AllowedResources)
            .WithDefaultTokenExchangeAudiences(newClientOptions.TokenExchangeAudiences)
            .WithOfflineAccessWithUserAgentAccessToken(newClientOptions.AllowOfflineAccessWithUserAgentAccessToken)
            .WithClientAssertionAudiences(newClientOptions.ClientAssertionAudiences.AdmittedBy(
                SecurityProfileRequirements.Resolve(tenant.DefaultSecurityProfile)))
            .Build();
    }
}
