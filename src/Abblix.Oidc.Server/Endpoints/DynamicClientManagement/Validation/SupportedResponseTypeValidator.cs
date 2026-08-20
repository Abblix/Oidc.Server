// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
