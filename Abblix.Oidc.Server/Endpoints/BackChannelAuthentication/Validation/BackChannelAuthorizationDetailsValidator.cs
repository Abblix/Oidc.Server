// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.AuthorizationDetails;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates the RFC 9396 §3 <c>authorization_details</c> array on a CIBA backchannel
/// authentication request. Mirrors the policy applied at <c>/authorize</c> and
/// <c>/par</c> in <c>AuthorizationDetailsRequestValidator</c>: per-client allowlist
/// (RFC 9396 §5.1), then per-type composite validator dispatch. Stores the validated
/// raw <see cref="System.Text.Json.Nodes.JsonArray"/> on the context so the
/// downstream <c>BackChannelAuthenticationRequestProcessor</c> can thread it onto
/// the <c>AuthorizationContext</c> for byte-exact emission on the issued access token.
/// </summary>
public class BackChannelAuthorizationDetailsValidator(
    IAuthorizationDetailsValidator detailsValidator) : IBackChannelAuthenticationContextValidator
{
    /// <inheritdoc/>
    public async Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
    {
        var rawRequested = context.Request.AuthorizationDetails;
        if (rawRequested is null || rawRequested.Count == 0)
            return null;

        var typedRequested = rawRequested.ToTypedArray();
        if (typedRequested is null || typedRequested.Length == 0)
            return null;

        var allowlist = context.ClientInfo.AuthorizationDetailsTypes;
        if (allowlist is not null)
        {
            if (allowlist.Length == 0)
            {
                return new OidcError(
                    ErrorCodes.InvalidAuthorizationDetails,
                    "Client is not permitted to use authorization_details.");
            }

            var allowedSet = new HashSet<string>(allowlist, StringComparer.Ordinal);
            var disallowed = typedRequested
                .Where(d => d.Type is not null && !allowedSet.Contains(d.Type))
                .Select(d => d.Type!)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (disallowed.Length != 0)
            {
                return new OidcError(
                    ErrorCodes.InvalidAuthorizationDetails,
                    $"Authorization detail types not allowed for this client: {string.Join(", ", disallowed)}");
            }
        }

        var result = await detailsValidator.ValidateAsync(typedRequested, context.ClientInfo, CancellationToken.None);
        if (!result.TryGetSuccess(out _))
        {
            return new OidcError(ErrorCodes.InvalidAuthorizationDetails, result.GetFailure().Description);
        }

        context.AuthorizationDetails = rawRequested;
        return null;
    }
}
