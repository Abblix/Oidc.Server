// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.AuthorizationDetails;

/// <summary>
/// Shared RFC 9396 <c>authorization_details</c> policy: per-client allowlist (§5.1) plus
/// per-type composite validator dispatch (§5). Endpoint-side validators (/authorize, /par,
/// CIBA backchannel auth, device authorization) delegate here so the policy lives in one
/// place; each endpoint converts the returned error description to its own error type.
/// </summary>
public static class AuthorizationDetailsPolicy
{
    /// <summary>
    /// Validates the raw <c>authorization_details</c> array against the per-client allowlist
    /// and the registered per-type validators.
    /// </summary>
    /// <param name="raw">The raw <c>authorization_details</c> array off the wire, or <c>null</c>
    /// / empty when the request did not carry one.</param>
    /// <param name="clientInfo">The authenticated client; <see cref="ClientInfo.AuthorizationDetailsTypes"/>
    /// drives the allowlist branch.</param>
    /// <param name="detailsValidator">The composite per-type validator registered by
    /// <c>AddRichAuthorizationRequests</c>.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to per-type validators.</param>
    /// <returns>
    /// On success — the raw <see cref="JsonArray"/> that survived validation byte-exact (or
    /// <c>null</c> when the input was null / empty / contained no typed entries — there is
    /// nothing to forward in that case). On failure — a human-readable description of the
    /// reason, which the caller wraps in its endpoint-specific error type with the
    /// <c>invalid_authorization_details</c> error code (RFC 9396 §5).
    /// </returns>
    public static async Task<Result<JsonArray?, string>> ApplyAsync(
        JsonArray? raw,
        ClientInfo clientInfo,
        IAuthorizationDetailsValidator detailsValidator,
        CancellationToken cancellationToken = default)
    {
        if (raw is not { Count: > 0 } jsonArray)
            return (JsonArray?)null;

        var authorizationDetails = jsonArray.ToTypedArray();
        if (authorizationDetails is not { Length: > 0 })
            return (JsonArray?)null;

        var allowlist = clientInfo.AuthorizationDetailsTypes;
        if (allowlist is not null)
        {
            if (allowlist.Length == 0)
                return "Client is not permitted to use authorization_details.";

            var allowedSet = new HashSet<string>(allowlist, StringComparer.Ordinal);
            var disallowed = authorizationDetails
                .Where(d => d.Type is not null && !allowedSet.Contains(d.Type))
                .Select(d => d.Type!)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (disallowed.Length != 0)
                return $"Authorization detail types not allowed for this client: {string.Join(", ", disallowed)}";
        }

        var result = await detailsValidator.ValidateAsync(authorizationDetails, clientInfo, cancellationToken);
        if (!result.TryGetSuccess(out _))
            return result.GetFailure().Description;

        return jsonArray;
    }
}
