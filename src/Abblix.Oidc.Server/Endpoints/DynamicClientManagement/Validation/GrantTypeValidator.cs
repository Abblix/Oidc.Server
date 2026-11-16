// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Enforces the correspondence between <c>response_types</c> and <c>grant_types</c> in both directions: a client
/// requesting <c>code</c> must register the <c>authorization_code</c> grant, and one requesting <c>token</c> or
/// <c>id_token</c> the <c>implicit</c> grant (OIDC DCR 1.0 section 2); and a client registering either of those grants
/// must request a response type carrying its part, since RFC 7591 section 2.1 pairs <c>authorization_code</c> with
/// <c>code</c> and <c>implicit</c> with <c>token</c>, and has the server "ensure that a client cannot register itself
/// into an inconsistent state". The grants the table pairs with no response type need none.
/// </summary>
public class GrantTypeValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// The grant types obtained through the authorization endpoint, each usable only with a response type that the
    /// table pairs with it.
    /// </summary>
    private static readonly string[] AuthorizationEndpointGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.Implicit];

    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error listing the grant types the client must register to support its
    /// declared response types, or those it registers without a response type to use them with, or <c>null</c> when
    /// the sets agree.
    /// </summary>
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        var pairedGrantTypes = new HashSet<string>(StringComparer.Ordinal);

        foreach (var responseType in request.ResponseTypes)
        {
            if (responseType.HasFlag(ResponseTypes.Code))
                pairedGrantTypes.Add(GrantTypes.AuthorizationCode);

            if (responseType.HasFlag(ResponseTypes.Token) || responseType.HasFlag(ResponseTypes.IdToken))
                pairedGrantTypes.Add(GrantTypes.Implicit);
        }

        var missingGrantTypes = pairedGrantTypes.Except(request.GrantTypes, StringComparer.Ordinal).ToArray();
        if (missingGrantTypes.Length > 0)
        {
            return ErrorFactory.InvalidClientMetadata(
                $"The following grant types are required: {string.Join(", ", missingGrantTypes)}");
        }

        var unpairedGrantTypes = AuthorizationEndpointGrantTypes
            .Intersect(request.GrantTypes, StringComparer.Ordinal)
            .Except(pairedGrantTypes, StringComparer.Ordinal)
            .ToArray();
        if (unpairedGrantTypes.Length > 0)
        {
            return ErrorFactory.InvalidClientMetadata(
                "The following grant types have no response type to use them with: " +
                string.Join(", ", unpairedGrantTypes));
        }

        return null;
    }
}
