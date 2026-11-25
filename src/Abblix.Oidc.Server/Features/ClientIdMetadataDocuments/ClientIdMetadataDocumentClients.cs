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
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
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
/// <param name="logger">Records a client resolved from its document, and why an identifier was not resolved.</param>
/// <param name="documents">The documents fetched and held.</param>
/// <param name="scopes">Opens the container a document is judged in, since the checks it passes are scoped services.
/// </param>
/// <param name="options">The host's settings, read on each lookup.</param>
/// <param name="environment">Whether the host runs in Production, where no document is fetched from loopback.</param>
internal sealed partial class ClientIdMetadataDocumentClients(
    IClientInfoProvider inner,
    ILogger<ClientIdMetadataDocumentClients> logger,
    HeldMetadataDocuments documents,
    IServiceScopeFactory scopes,
    IOptionsMonitor<OidcOptions> options,
    ProductionEnvironment environment) : IClientInfoProvider
{
    /// <inheritdoc />
    public async Task<Result<ClientInfo, ClientAbsence>> FindClientAsync(TenantDefinition tenant, string clientId)
    {
        // A store the host registered may answer with a client held under another spelling of the URL, which section 3
        // has compared "using simple string comparison": that client is not the one the URL names
        var stored = await inner.FindClientAsync(tenant, clientId);
        if (stored.TryGetSuccess(out var storedClient) && storedClient.IsNamedBy(clientId))
            return stored;

        var settings = options.CurrentValue;
        var url = Fetched(tenant, clientId, settings, out var rule);
        if (url is null)
            return NamesAUrl(clientId) ? ClientAbsence.Refused : ClientAbsence.Unknown;

        var held = await documents.GetAsync(clientId, url, rule);
        if (!held.TryGetSuccess(out var document))
            return held.GetFailure().MayPass ? ClientAbsence.TemporarilyUnavailable : ClientAbsence.Refused;

        if (document.ClientAt(tenant) is { } heldClient)
            return heldClient;

        var read = await documents.ReadAtAsync(tenant, clientId, document);
        if (!read.TryGetSuccess(out var metadata))
        {
            LogClientRefused(clientId, tenant.Id, read.GetFailure().Reason);
            return ClientAbsence.Refused;
        }

        var client = await JudgeAsync(tenant, clientId, metadata, settings);

        // A refusal is not kept: section 6.2 has the server "MUST NOT cache documents which are invalid", and one is so
        // at this tenant
        if (client is null)
            return ClientAbsence.Refused;

        return Keep(tenant, document, client);
    }

    /// <summary>
    /// Holds <paramref name="client"/>, the client <paramref name="document"/> describes at <paramref name="tenant"/>,
    /// with the document for the tenant's generation, unless a lookup racing this one held its own first, and answers
    /// with the client held.
    /// </summary>
    /// <remarks>
    /// The lookup whose client is held records it, so a document is recorded once per tenant generation however many
    /// requests read the client it holds; a document fetched again once its copy expires holds, and records, its
    /// client anew. A scope left unset is recorded as absent, which leaves the client any scope. Internal rather than
    /// private so a test can play the lookup that loses the race, which no request can be made to lose on demand.
    /// </remarks>
    internal ClientInfo Keep(TenantDefinition tenant, HeldMetadataDocument document, ClientInfo client)
    {
        if (!document.TryHold(tenant, client, out var held))
            return held;

        LogClientResolved(
            tenant.Id,
            client.ClientId,
            Sanitized.Values(client.EffectiveGrantTypes),
            Sanitized.Values(client.AllowedScopes),
            client.AllowedResources);

        return client;
    }

    /// <summary>
    /// Whether <paramref name="clientId"/> is written as an <c>https</c> URL, which only a client identifier URL is: an
    /// identifier that is not names no document, and its client is unknown like any other.
    /// </summary>
    private static bool NamesAUrl(string clientId)
        => clientId.StartsWith(Uri.UriSchemeHttps + Uri.SchemeDelimiter, StringComparison.Ordinal);

    /// <summary>
    /// The URL to fetch <paramref name="clientId"/>'s document from, or null when it is not fetched.
    /// </summary>
    private Uri? Fetched(TenantDefinition tenant, string clientId, OidcOptions settings, out OutboundAddressRule rule)
    {
        // Decided at each lookup, a held document's included, so a tenant whose issuer is not on loopback is never
        // served a document another tenant's fetch reached loopback for
        var addresses = settings.ClientIdMetadataDocuments.DocumentAddresses;
        rule = SpecialPurposeFetches.DocumentRuleAt(tenant.Issuer, addresses, environment.IsCurrent);

        // Said apart from every other refusal, so a host that set the exception reads why this tenant does not get it
        if (Uri.TryCreate(clientId, UriKind.Absolute, out var named) &&
            SpecialPurposeFetches.LoopbackWithheldAt(tenant.Issuer, addresses, environment.IsCurrent, named))
        {
            LogLoopbackWithheld(clientId, tenant.Id, tenant.Issuer);
            return null;
        }

        var why = ClientIdentifierUrl.WhyNotFetched(clientId, rule, out var url);
        if (why is not null)
        {
            // An identifier that is no URL at all is an unknown client like any other, and says nothing worth a line
            if (NamesAUrl(clientId))
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
    /// accepts. The issuer is compared in its normalized spelling alone: a client_id reaching this check is written in
    /// the form it is requested in (<see cref="ClientIdentifierUrl"/>), so it can equal the issuer as written only
    /// where that is the normalized spelling too.
    /// </remarks>
    private static bool NamesAServer(TenantDefinition tenant, string clientId, OidcOptions settings)
    {
        IEnumerable<string> servers =
        [
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
        OidcOptions settings)
    {
        var newClientOptions = settings.NewClientOptions;
        await using var scope = scopes.CreateAsyncScope();
        var validator = ActivatorUtilities.CreateInstance<ClientIdMetadataDocumentValidator>(scope.ServiceProvider);

        // The checks fetch what the document names, its sector identifier among them, on the document's behalf
        using var strict = SpecialPurposeFetches.Enter();

        var judged = await validator.ValidateAsync(tenant, metadata);
        if (!judged.TryGetSuccess(out var context))
        {
            LogClientRefused(clientId, tenant.Id, judged.GetFailure().ErrorDescription);
            return null;
        }

        // Built as a newly registered client is, with the host's defaults for what the metadata leaves unnamed. No
        // secret: section 4.1 leaves a document none
        var client = new ClientInfoBuilder(clientId, context.Request)
            .WithSectorIdentifier(context.SectorIdentifier)
            .WithHostSettingsOf(newClientOptions)
            .WithDefaultScope(newClientOptions.Scope)
            .WithDefaultOfflineAccess(newClientOptions.OfflineAccess)
            .WithDefaultAllowedResources(newClientOptions.AllowedResources)
            .WithDefaultTokenExchangeAudiences(newClientOptions.TokenExchangeAudiences)
            .WithOfflineAccessWithUserAgentAccessToken(newClientOptions.AllowOfflineAccessWithUserAgentAccessToken)
            .WithClientAssertionAudiences(newClientOptions.ClientAssertionAudiences.AdmittedBy(
                SecurityProfileRequirements.Resolve(tenant.DefaultSecurityProfile)))
            .Build();

        // Every later fetch of the client's URIs is held to the registries as written (section 10.7)
        client.ResolvedFromMetadataDocument = true;

        // Decided as the client is resolved and held with it: a list of prefixes is the host's own assessment of the URLs
        // it serves, and without one any URL may name itself a client
        client.Trust = OpenRegistration.AdmitsAnyDocument(settings) ? ClientTrust.Untrusted : ClientTrust.Trusted;
        return client;
    }
}
