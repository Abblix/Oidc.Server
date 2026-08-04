// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Server-level support gate for the <c>response_types</c> registration parameter
/// (OIDC DCR §3.2): every part of every requested combination must have a registered
/// <see cref="IAuthorizationResponseBuilder"/>. Without <c>EnableImplicitFlow()</c> the
/// <c>token</c> / <c>id_token</c> processors are absent - registration must reject those
/// values with <c>invalid_client_metadata</c> at registration time, instead of letting the
/// client succeed at registration and fail with <c>unsupported_response_type</c> on its first
/// authorization request.
/// </summary>
/// <param name="processors">Registered per-response-type processors. Same source of truth
/// used by <c>FlowTypeValidator</c> at the authorization endpoint, so registration and
/// run-time gating cannot drift.</param>
public class SupportedResponseTypeValidator(IEnumerable<IAuthorizationResponseBuilder> processors)
    : SyncClientRegistrationContextValidator
{
    private readonly IReadOnlySet<string> _supportedResponseTypeParts = processors
        .Select(p => p.ResponseType)
        .ToHashSet(StringComparer.Ordinal);

    /// <inheritdoc />
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var unsupported = context.Request.ResponseTypes
            .SelectMany(combo => combo)
            .Where(part => !_supportedResponseTypeParts.Contains(part))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (unsupported.Length != 0)
        {
            return ErrorFactory.InvalidClientMetadata(
                $"The following response types are not supported by this server: {string.Join(", ", unsupported)}");
        }

        return null;

    }
}
