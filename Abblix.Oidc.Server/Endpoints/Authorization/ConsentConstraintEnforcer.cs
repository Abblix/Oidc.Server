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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Default <see cref="IConsentConstraintEnforcer"/>. Asserts <c>granted ⊆ requested</c> for scopes,
/// resources (including their nested scopes) and RFC 9396 <c>authorization_details</c>, throwing
/// when the consent provider returned anything outside the request.
/// </summary>
/// <param name="authorizationDetailsPolicy">Re-runs granted <c>authorization_details</c> through the
/// per-type validators and per-client allowlist; the per-type validator owns the "is B a narrowing
/// of A" decision for intra-entry content (RFC 9396 has no universal comparator).</param>
public class ConsentConstraintEnforcer(
    IAuthorizationDetailsPolicy authorizationDetailsPolicy) : IConsentConstraintEnforcer
{
    /// <inheritdoc />
    public async Task EnforceAsync(
        ValidAuthorizationRequest request,
        ConsentDefinition granted,
        CancellationToken cancellationToken)
    {
        EnforceScopes(request, granted);
        EnforceResources(request, granted);
        await EnforceAuthorizationDetailsAsync(request, granted, cancellationToken);
    }

    private static void EnforceScopes(ValidAuthorizationRequest request, ConsentDefinition granted)
    {
        var requested = request.Scope.Select(s => s.Scope).ToHashSet(StringComparer.Ordinal);

        var escaped = granted.Scopes
            .Select(s => s.Scope)
            .Where(scope => !requested.Contains(scope))
            .ToArray();

        if (escaped.Length > 0)
            throw Violation("scopes", escaped);
    }

    private static void EnforceResources(ValidAuthorizationRequest request, ConsentDefinition granted)
    {
        // Map each requested resource URI to the set of scopes requested for it. Built defensively
        // against duplicate resource entries (scopes merged) so a malformed request can't crash the
        // guard before it does its job.
        var requested = new Dictionary<Uri, HashSet<string>>();
        foreach (var resource in request.Resources)
        {
            if (!requested.TryGetValue(resource.Resource, out var scopes))
                requested[resource.Resource] = scopes = new HashSet<string>(StringComparer.Ordinal);

            foreach (var scope in resource.Scopes)
                scopes.Add(scope.Scope);
        }

        foreach (var grantedResource in granted.Resources)
        {
            if (!requested.TryGetValue(grantedResource.Resource, out var requestedScopes))
                throw Violation("resources", [grantedResource.Resource.OriginalString]);

            // RFC 8707: a resource indicator scopes down. The granted resource's nested scopes must
            // not exceed what was requested for that same resource.
            var escapedScopes = grantedResource.Scopes
                .Select(s => s.Scope)
                .Where(scope => !requestedScopes.Contains(scope))
                .ToArray();

            if (escapedScopes.Length > 0)
                throw Violation($"scopes for resource '{grantedResource.Resource}'", escapedScopes);
        }
    }

    private async Task EnforceAuthorizationDetailsAsync(
        ValidAuthorizationRequest request,
        ConsentDefinition granted,
        CancellationToken cancellationToken)
    {
        if (granted.AuthorizationDetails is not { Count: > 0 } grantedAuthorizationDetails)
            return;

        // Type-level subset: every granted entry's type must appear among the requested types. The
        // per-client allowlist (re-checked below) is not enough on its own — a client allowed types
        // {A, B} that requested only {A} must not have a {B} entry injected by the consent decision.
        var requestedTypes = (request.AuthorizationDetails?.ToTypedArray() ?? [])
            .Select(detail => detail.Type)
            .Where(type => type is not null)
            .ToHashSet(StringComparer.Ordinal);

        var escapedTypes = (grantedAuthorizationDetails.ToTypedArray() ?? [])
            .Select(detail => detail.Type)
            .Where(type => type is not null && !requestedTypes.Contains(type))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (escapedTypes.Length > 0)
            throw Violation("authorization_details types", escapedTypes!);

        // Intra-entry narrowing: RFC 9396 defines no universal comparator for "is B a narrowing of
        // A" (an amount, a locations list within one entry), so re-run the granted entries through
        // the per-type validators and per-client allowlist and let the per-type validator own that
        // decision. A rejection means a granted entry's content escalated beyond what the validator
        // permits for this client.
        var revalidation = await authorizationDetailsPolicy.ApplyAsync(
            grantedAuthorizationDetails, request.ClientInfo, cancellationToken);

        if (revalidation.TryGetFailure(out var error))
        {
            throw new InvalidOperationException(
                "The IUserConsentsProvider granted authorization_details that fail per-type re-validation, " +
                "so the granted set is not a valid narrowing of the request " +
                $"(the consent provider violated the granted ⊆ requested contract): {error.ErrorDescription}");
        }
    }

    private static InvalidOperationException Violation(string category, string[] escaped) =>
        new($"The IUserConsentsProvider granted {category} absent from the authorization request: " +
            $"{string.Join(", ", escaped)}. The granted set must be a subset of what the request carried " +
            "(granted ⊆ requested); returning a broader set violates the IUserConsentsProvider " +
            "contract documented on ConsentDefinition and would let the end-user escalate their own grant.");
}
