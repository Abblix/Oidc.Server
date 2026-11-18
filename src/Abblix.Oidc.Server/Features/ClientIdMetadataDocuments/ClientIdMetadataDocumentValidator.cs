// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// Judges the metadata a client's document describes it with by the checks a dynamic client registration passes
/// (RFC 7591 section 2 and the extensions this server supports), each built from the container of the request.
/// </summary>
/// <remarks>
/// Section 4 of draft-ietf-oauth-client-id-metadata-document takes the document's values from "the OAuth Dynamic
/// Client Registration Metadata OAuth Parameters registry ... as established by [RFC7591]", so they are judged as a
/// registration's are, the host's limits on what a new client gets included. Two checks of the registration pipeline
/// are left out because they judge the request rather than the metadata: the initial access token, which a fetched
/// document cannot carry, and whether the requested client_id is taken, which asks the client store for the very
/// identifier being resolved. The checks are built here rather than resolved, since a host need not open dynamic
/// registration to accept clients by their documents, and they are the registration pipeline's own list, so a check
/// added there judges a document too.
/// </remarks>
/// <param name="services">The container of the request the client is resolved for.</param>
internal sealed class ClientIdMetadataDocumentValidator(IServiceProvider services)
{
    /// <summary>
    /// Runs the checks over <paramref name="metadata"/> at <paramref name="tenant"/>.
    /// </summary>
    /// <param name="tenant">The tenant the client is resolved at.</param>
    /// <param name="metadata">The metadata the document describes the client with.</param>
    /// <returns>The context the checks leave, the sector identifier resolved among it, or the first refusal.</returns>
    public async Task<Result<ClientRegistrationValidationContext, OidcError>> ValidateAsync(
        TenantDefinition tenant,
        ClientRegistrationRequest metadata)
    {
        var context = new ClientRegistrationValidationContext(metadata);
        foreach (var step in ClientRegistrationMetadataChecks.All)
        {
            var validator = (IClientRegistrationContextValidator)ActivatorUtilities.CreateInstance(
                services, step.ImplementationType!);
            if (await validator.ValidateAsync(tenant, context) is { } error)
                return error;
        }

        return context;
    }
}
