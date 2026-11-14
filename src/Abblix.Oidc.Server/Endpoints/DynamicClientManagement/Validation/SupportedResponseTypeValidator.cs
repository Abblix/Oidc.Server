// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Server-level support gate for the <c>response_types</c> registration parameter
/// (OIDC DCR section 3.2): every part of every requested combination must have a registered
/// <see cref="IAuthorizationResponseBuilder"/>. Without <c>EnableImplicitFlow()</c> the
/// <c>token</c> / <c>id_token</c> processors are absent - registration must reject those
/// values with <c>invalid_client_metadata</c> at registration time, instead of letting the
/// client succeed at registration and fail with <c>unsupported_response_type</c> on its first
/// authorization request. The <c>response_modes</c> parameter of FAPI 2.0 Message Signing section 5.3.3 is gated
/// the same way, against the <c>response_modes_supported</c> discovery advertises.
/// </summary>
/// <param name="processors">Registered per-response-type processors. Same source of truth
/// used by <c>FlowTypeValidator</c> at the authorization endpoint and by discovery, so registration and
/// run-time gating cannot drift.</param>
public class SupportedResponseTypeValidator(IEnumerable<IAuthorizationResponseBuilder> processors)
    : SyncClientRegistrationContextValidator
{
    private readonly IReadOnlySet<string> _supportedResponseTypeParts = processors
        .Select(p => p.ResponseType)
        .ToHashSet(StringComparer.Ordinal);

    private readonly IReadOnlySet<string> _supportedResponseModes = AuthorizationEndpointMetadataFactory
        .Create(processors)
        .ResponseModesSupported
        .ToHashSet(StringComparer.Ordinal);

    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        // An empty string names no response type; registered, it would be a combination no authorization request
        // can match, and the client would be refused on every request after a successful registration
        if (context.Request.ResponseTypes.Any(combination => combination.Length == 0))
            return ErrorFactory.InvalidClientMetadata("An empty value is not a response type");

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

        return WhyResponseModesRefused(context.Request.ResponseModes);
    }

    /// <summary>
    /// Why the <c>response_modes</c> a registration names are refused, or null where they are not. Omitted, the
    /// parameter means "the client may use any of the response modes supported by the authorization server" (FAPI 2.0
    /// Message Signing section 5.3.3).
    /// </summary>
    private OidcError? WhyResponseModesRefused(string[]? responseModes)
    {
        if (responseModes is null)
            return null;

        // An empty list is not an omitted one: it admits no response mode, so every authorization request the client
        // could send would be refused after a successful registration
        if (responseModes.Length == 0)
            return ErrorFactory.InvalidClientMetadata("The response modes name no response mode");

        var unsupported = responseModes
            .Where(mode => !_supportedResponseModes.Contains(mode))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return unsupported.Length == 0
            ? null
            : ErrorFactory.InvalidClientMetadata(
                $"The following response modes are not supported by this server: {string.Join(", ", unsupported)}");
    }
}
