// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.AuthorizationDetails;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the RFC 9396 <c>authorization_details</c> array on an authorization request:
/// applies the per-client <see cref="Features.ClientInformation.ClientInfo.AuthorizationDetailsTypes"/>
/// allowlist (RFC 9396 §5.1), then defers per-type schema validation to the composite
/// <see cref="IAuthorizationDetailsValidator"/> registered by the host. The validated array is
/// stashed on the context so downstream emitters (grant carriage, token response, introspection)
/// see the post-validation value.
/// </summary>
/// <param name="detailsValidator">The composite validator that dispatches each entry to its
/// keyed-by-<c>type</c> per-type implementation. Registered unconditionally by
/// <c>AddRichAuthorizationRequests</c>, so this dependency resolves on every deployment — even
/// those that have not registered any per-type validators (in which case any non-empty
/// authorization_details array is rejected with <c>invalid_authorization_details</c>, the
/// RFC 9396 §5 MUST-refuse behaviour for unknown types).</param>
public class AuthorizationDetailsRequestValidator(
    IAuthorizationDetailsValidator detailsValidator) : IAuthorizationContextValidator
{
    /// <inheritdoc/>
    public async Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
    {
        var requested = context.Request.AuthorizationDetails;
        if (requested is null || requested.Length == 0)
            return null;

        var allowlist = context.ClientInfo.AuthorizationDetailsTypes;
        if (allowlist is not null)
        {
            // RFC 9396 §5.1: per-client allowlist. Empty array means «client cannot use RAR».
            // Non-empty array means only the listed types are accepted for this client.
            if (allowlist.Length == 0)
            {
                return context.InvalidAuthorizationDetails(
                    "Client is not permitted to use authorization_details.");
            }

            var allowedSet = new HashSet<string>(allowlist, StringComparer.Ordinal);
            var disallowed = requested
                .Where(d => d.Type is not null && !allowedSet.Contains(d.Type))
                .Select(d => d.Type!)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (disallowed.Length != 0)
            {
                return context.InvalidAuthorizationDetails(
                    $"Authorization detail types not allowed for this client: {string.Join(", ", disallowed)}");
            }
        }

        var result = await detailsValidator.ValidateAsync(requested, context.ClientInfo, CancellationToken.None);
        if (!result.TryGetSuccess(out var validated))
        {
            return context.InvalidAuthorizationDetails(result.GetFailure().Description);
        }

        context.AuthorizationDetails = validated.ToArray();
        return null;
    }
}
