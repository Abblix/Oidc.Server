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

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.AuthorizationDetails;

/// <summary>
/// Composite implementation of <see cref="IAuthorizationDetailsValidator"/>. Dispatches each
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
internal sealed class AuthorizationDetailsValidator(
    IServiceProvider serviceProvider) : IAuthorizationDetailsValidator
{
    /// <inheritdoc/>
    public async Task<Result<IReadOnlyList<AuthorizationDetail>, AuthorizationDetailValidationError>> ValidateAsync(
        IEnumerable<AuthorizationDetail> details,
        ClientInfo client,
        CancellationToken ct)
    {
        var validated = new List<AuthorizationDetail>();

        foreach (var detail in details)
        {
            if (string.IsNullOrEmpty(detail.Type))
            {
                return new AuthorizationDetailValidationError(
                    "authorization_details entry is missing the required 'type' member (RFC 9396 §2)");
            }

            var validator = serviceProvider.GetKeyedService<IAuthorizationDetailValidator>(detail.Type);
            if (validator is null)
            {
                return new AuthorizationDetailValidationError(
                    $"unknown authorization_details type: '{detail.Type}'");
            }

            var result = await validator.ValidateAsync(detail, client, ct);
            if (!result.TryGetSuccess(out var validDetail))
            {
                return result.GetFailure();
            }

            validated.Add(validDetail);
        }

        return validated;
    }
}
