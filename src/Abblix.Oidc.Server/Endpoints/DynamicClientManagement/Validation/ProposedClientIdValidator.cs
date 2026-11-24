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
/// Drops the <c>client_id</c> a new registration proposes, so the server assigns one, unless the host lets registrants
/// choose it (<see cref="NewClientOptions.AcceptProposedClientId"/>).
/// </summary>
/// <remarks>
/// RFC 9700 section 4.15.1: the server "SHOULD NOT allow clients to influence their client_id". RFC 7591 defines
/// <c>client_id</c> only in the response, as an identifier "issued by the authorization server" (section 2, under
/// <c>software_id</c>), and lets the server replace a requested value with one of its own (section 2). The proposal
/// is dropped rather than refused, so the steps after this one, which judge a proposed identifier, see none. An
/// update keeps the client_id RFC 7592 section 2.2 requires it to carry, so it is not touched here.
/// </remarks>
/// <param name="options">Says whether the host lets registrants choose their client_id, read on each
/// registration.</param>
internal sealed class ProposedClientIdValidator(IOptionsMonitor<OidcOptions> options)
    : SyncClientRegistrationContextValidator
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        if (context is { Operation: DynamicClientOperation.Register, Request.ClientId: not null } &&
            !options.CurrentValue.NewClientOptions.AcceptProposedClientId)
        {
            context.Request = context.Request with { ClientId = null };
        }

        return null;
    }
}
