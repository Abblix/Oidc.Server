// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// slice #132 - no <c>TryAddEnumerable</c> parallel slot. Lookup that returns <c>null</c>
/// (no host registration for the requested type) yields
/// <c>invalid_authorization_details</c> per RFC 9396 §5, never throws - the server boots
/// cleanly with zero per-type validators and rejects RAR requests with a structured error.
/// </remarks>
internal sealed class AuthorizationDetailsPolicy(
    IServiceProvider serviceProvider) : IAuthorizationDetailsPolicy
{
    /// <summary>
    /// The per-entry question, which is the only thing the request phase and the granted phase differ
    /// in: everything around it (object shape, known type, per-client allowlist) binds in both.
    /// </summary>
    private delegate Task<Result<AuthorizationDetail, OidcError>> AskValidator(
        IAuthorizationDetailValidator validator,
        AuthorizationDetail detail,
        ClientInfo client,
        CancellationToken token);

    /// <inheritdoc/>
    public Task<Result<JsonArray?, OidcError>> ApplyAsync(
        JsonArray? raw,
        ClientInfo client,
        CancellationToken token)
        => ApplyCoreAsync(
            raw,
            client,
            static (validator, detail, client, token) => validator.ValidateAsync(detail, client, token),
            token);

    /// <inheritdoc/>
    public Task<Result<JsonArray?, OidcError>> ApplyGrantedAsync(
        JsonArray? granted,
        ClientInfo client,
        CancellationToken token)
        => ApplyCoreAsync(
            granted,
            client,
            static (validator, detail, client, token) => validator.ValidateGrantedAsync(detail, client, token),
            token);

    private async Task<Result<JsonArray?, OidcError>> ApplyCoreAsync(
        JsonArray? raw,
        ClientInfo client,
        AskValidator ask,
        CancellationToken token)
    {
        if (raw is not { Count: > 0 })
            return (JsonArray?)null;

        // An entry that is not a JSON object is dropped by the conversion, so a count that shrank means the
        // client sent authorization_details this server cannot read - ["payment"] or [1,2] rather than the
        // objects RFC 9396 section 2 defines. Refused rather than quietly reduced: the null the conversion
        // would otherwise produce is indistinguishable from the client having sent none, so the request
        // would be authorized with its authorization_details silently discarded, which is the one outcome
        // neither the client nor the resource server can detect.
        if (raw.ToTypedArray() is not { } authorizationDetails || authorizationDetails.Length != raw.Count)
            return Reject("Every authorization_details entry must be a JSON object.");

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

        var result = await ValidateAsync(authorizationDetails, client, ask, token);

        // Rebuild the raw array from the validated typed list (RFC 9396 §7.1 narrow / extend).
        // When per-type validators left their input untouched the result is byte-equivalent
        // to the original - DeepClone in ToRawJsonArray preserves member order and any
        // type-specific payload. When a validator returned a modified AuthorizationDetail,
        // that mutation surfaces here and the pipeline forwards the post-validation shape
        // (not the original request) into AuthorizationContext, so token emission reflects
        // what was actually granted.
        return result.MapSuccess(success => success.ToRawJsonArray());
    }

    private async Task<Result<IReadOnlyList<AuthorizationDetail>, OidcError>> ValidateAsync(
        IEnumerable<AuthorizationDetail> details,
        ClientInfo client,
        AskValidator ask,
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
                return new OidcError(
                    ErrorCodes.InvalidAuthorizationDetails,
                    $"unknown authorization_details type: '{detail.Type}'");
            }

            var result = await ask(validator, detail, client, cancellationToken);
            if (result.TryGetFailure(out var failure))
            {
                return failure;
            }

            validated.Add(result.GetSuccess());
        }

        return validated;
    }

    private static OidcError Reject(string description) =>
        new(ErrorCodes.InvalidAuthorizationDetails, description);
}
