// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Refuses an RFC 7592 update carrying a <c>client_secret</c> that is not the client's: section 2.2 says "If the client
/// includes the "client_secret" field in the request, the value of this field MUST match the currently issued client
/// secret for that client". An update carrying none, and a new registration, are left alone.
/// </summary>
/// <remarks>
/// The section names no error of its own and sends an invalid field to the RFC 7591 section 3.2.2 errors, of which
/// invalid_client_metadata is the one for "The value of one of the client metadata fields is invalid". The secret
/// presented is compared against the stored hashes, as the token endpoint compares it, expiry aside: an expired
/// secret is still the one currently issued.
/// </remarks>
/// <param name="hashService">Hashes the presented secret, since only its hashes are stored.</param>
internal sealed class UpdateClientSecretValidator(IHashService hashService) : SyncClientRegistrationContextValidator
{
    private readonly ClientSecretMatcher _matcher = new(hashService);

    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        if (context is not { Operation: DynamicClientOperation.Update, Request.ClientSecret: { } secret })
            return null;

        var storedClient = context.StoredClient ?? throw new InvalidOperationException(
            $"An update is judged without the {nameof(context.StoredClient)} it replaces");

        if (_matcher.FindMatching(storedClient, secret).Any())
            return null;

        return ErrorFactory.InvalidClientMetadata("The client_secret is not the one currently issued to the client");
    }
}
