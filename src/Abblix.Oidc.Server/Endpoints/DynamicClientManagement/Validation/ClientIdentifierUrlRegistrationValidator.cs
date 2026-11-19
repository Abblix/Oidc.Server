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
/// Refuses a registration naming an <c>https</c> URL as its client_id while the server resolves clients from the
/// metadata documents such URLs name.
/// </summary>
/// <remarks>
/// A registration is found before a document is fetched, so a registrant naming somebody else's client identifier URL
/// would be served in that client's place, with redirect URIs of its own choosing. draft-ietf-oauth-client-id-metadata-
/// document section 9.1 has a server supporting both "ensure that the client_id strings it generates do not start with
/// https://"; a client_id the registrant proposes is one this server would otherwise assign. It runs before the check
/// that the client_id is free, which would look the URL up and so fetch its document. An update keeps the client_id
/// the client already has, so it is not judged here.
/// </remarks>
/// <param name="options">Says whether clients are resolved from their documents, read on each registration.</param>
internal sealed class ClientIdentifierUrlRegistrationValidator(IOptionsMonitor<OidcOptions> options)
    : SyncClientRegistrationContextValidator
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
        => context is { Operation: DynamicClientOperation.Register, Request.ClientId: { } clientId } &&
           options.CurrentValue.ClientIdMetadataDocuments.Enabled &&
           clientId.StartsWith(Uri.UriSchemeHttps + Uri.SchemeDelimiter, StringComparison.Ordinal)
            ? ErrorFactory.InvalidClientMetadata(
                $"A {Parameters.ClientId} starting with {Uri.UriSchemeHttps}{Uri.SchemeDelimiter} names a client " +
                "identifier URL, which is resolved from its own metadata document rather than registered")
            : null;
}
