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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.RichAuthorizationRequests;

/// <summary>
/// Composite implementation of <see cref="IAuthorizationDetailsPolicy"/>. Dispatches each
/// authorization_details entry to the matching <see cref="IAuthorizationDetailValidator"/>
/// resolved via <see cref="ServiceProviderKeyedServiceExtensions.GetKeyedService"/> using the
/// entry's <c>type</c> value as the key.
/// </summary>
/// <remarks>
/// The single keyed registration done by
/// <see cref="ServiceCollectionExtensions.AddAuthorizationDetailValidator{TValidator}"/>
/// serves both O(1) request-time dispatch (this class) and discovery enumeration via
/// <c>GetKeyedServices&lt;IAuthorizationDetailValidator&gt;(KeyedService.AnyKey)</c> in
/// slice #132 — no <c>TryAddEnumerable</c> parallel slot. Lookup that returns <c>null</c>
/// (no host registration for the requested type) yields
/// <c>invalid_authorization_details</c> per RFC 9396 §5, never throws — the server boots
/// cleanly with zero per-type validators and rejects RAR requests with a structured error.
/// </remarks>
internal sealed class AuthorizationDetailsPolicy(
    IServiceProvider serviceProvider) : IAuthorizationDetailsPolicy
{
    /// <inheritdoc/>
    public async Task<Result<JsonArray?, OidcError>> ApplyAsync(
        JsonArray? raw,
        ClientInfo client,
        CancellationToken token = default)
    {
        if (raw is not { Count: > 0 })
            return (JsonArray?)null;

        var authorizationDetails = raw.ToTypedArray();
        if (authorizationDetails is not { Length: > 0 })
            return (JsonArray?)null;

        var allowlist = client.AuthorizationDetailsTypes;
        if (allowlist is not null)
        {
            if (allowlist.Length == 0)
                return Reject("Client is not permitted to use authorization_details.");

            var allowedSet = new HashSet<string>(allowlist, StringComparer.Ordinal);

            var disallowed = authorizationDetails
                .Where(d => d.Type is not null && !allowedSet.Contains(d.Type))
                .Select(d => d.Type!)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (disallowed.Length != 0)
                return Reject($"Authorization detail types not allowed for this client: {string.Join(", ", disallowed)}");
        }

        var result = await ValidateAsync(authorizationDetails, client, token);
        if (!result.TryGetSuccess(out var validated))
            return result.GetFailure();

        // Rebuild the raw array from the validated typed list (RFC 9396 §5 narrow / extend).
        // When per-type validators left their input untouched the result is byte-equivalent
        // to the original — DeepClone in ToRawJsonArray preserves member order and any
        // type-specific payload. When a validator returned a modified AuthorizationDetail,
        // that mutation surfaces here and the pipeline forwards the post-validation shape
        // (not the original request) into AuthorizationContext, so token emission reflects
        // what was actually granted.
        return validated.ToRawJsonArray();
    }

    private async Task<Result<IReadOnlyList<AuthorizationDetail>, OidcError>> ValidateAsync(
        IEnumerable<AuthorizationDetail> details,
        ClientInfo client,
        CancellationToken cancellationToken)
    {
        var validated = new List<AuthorizationDetail>();

        foreach (var detail in details)
        {
            if (string.IsNullOrEmpty(detail.Type))
            {
                return new OidcError(ErrorCodes.InvalidAuthorizationDetails, 
                    "authorization_details entry is missing the required 'type' member (RFC 9396 §2)");
            }

            var validator = serviceProvider.GetKeyedService<IAuthorizationDetailValidator>(detail.Type);
            if (validator is null)
            {
                return new OidcError(ErrorCodes.InvalidAuthorizationDetails, 
                    $"unknown authorization_details type: '{detail.Type}'");
            }

            var result = await validator.ValidateAsync(detail, client, cancellationToken);
            if (!result.TryGetSuccess(out var validDetail))
            {
                return result.GetFailure();
            }

            validated.Add(validDetail);
        }

        return validated;
    }

    private static OidcError Reject(string description) =>
        new(ErrorCodes.InvalidAuthorizationDetails, description);
}
