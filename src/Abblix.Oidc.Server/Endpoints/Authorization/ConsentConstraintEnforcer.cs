// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
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
    public async Task<JsonArray?> EnforceAsync(
        ValidAuthorizationRequest request,
        ConsentDefinition granted,
        CancellationToken cancellationToken)
    {
        EnforceScopes(request, granted);
        EnforceResources(request, granted);
        return await EnforceAuthorizationDetailsAsync(request, granted, cancellationToken);
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

    private async Task<JsonArray?> EnforceAuthorizationDetailsAsync(
        ValidAuthorizationRequest request,
        ConsentDefinition granted,
        CancellationToken cancellationToken)
    {
        if (granted.AuthorizationDetails is not { Count: > 0 } grantedAuthorizationDetails)
            return null;

        // Type-level subset: every granted entry's type must appear among the requested types. The
        // per-client allowlist (re-checked below) is not enough on its own - a client allowed types
        // {A, B} that requested only {A} must not have a {B} entry injected by the consent decision.
        var requestedTypes = (request.AuthorizationDetails?.ToTypedArray() ?? [])
            .Select(detail => detail.Type)
            .OfType<string>()
            .ToHashSet(StringComparer.Ordinal);

        var grantedTypes = RefuseTypesOutside(requestedTypes, grantedAuthorizationDetails);

        // Intra-entry narrowing: RFC 9396 defines no universal comparator for "is B a narrowing of
        // A" (an amount, a locations list within one entry), so re-run the granted entries through
        // the per-type validators and per-client allowlist and let the per-type validator own that
        // decision. A rejection means a granted entry's content escalated beyond what the validator
        // permits for this client.
        var revalidation = await authorizationDetailsPolicy.ApplyAsync(
            grantedAuthorizationDetails, request.ClientInfo, cancellationToken);

        if (!revalidation.TryGetSuccess(out var revalidated))
        {
            throw new InvalidOperationException(
                "The IUserConsentsProvider granted authorization_details that fail per-type re-validation, " +
                "so the granted set is not a valid narrowing of the request " +
                "(the consent provider violated the granted ⊆ requested contract): " +
                revalidation.GetFailure().ErrorDescription);
        }

        // Nothing at all means nothing to change, which is how the request-time, CIBA and device
        // validators read the same result, so the granted array stands as it was.
        if (revalidated is null)
            return grantedAuthorizationDetails;

        // An EMPTY array is a different statement, and this request has already decided what it means:
        // a consent decision granting no entries against a request that carried some answers
        // access_denied, one step before this call. Reaching here with one says the validators removed
        // every entry, so returning the granted set would put back exactly what they removed.
        if (revalidated.Count == 0)
        {
            throw new InvalidOperationException(
                "The per-type re-validation of the granted authorization_details returned an empty set. " +
                "A policy signals 'nothing to change' by returning null; an empty array says every entry " +
                "was removed, and there is no set left to issue a grant for.");
        }

        // What comes back is the decision, not a copy of what went in: a validator narrowing an entry
        // says so by returning the narrowed one. Returning the granted array here instead would
        // re-derive from raw input the fact this call just computed, and every entry the two disagree
        // on would travel in the form nobody approved.
        //
        // Which is also why the type check has to run again, and against what the consent decision
        // GRANTED rather than against what was requested: nothing in the per-type validator's contract
        // stops the entry it returns from carrying another type, and a type the request carried but the
        // user did not grant is one this array must not bring back.
        RefuseTypesOutside(grantedTypes, revalidated);
        return revalidated;

        HashSet<string> RefuseTypesOutside(HashSet<string> allowed, JsonArray details)
        {
            // ToTypedArray drops whatever is not a JSON object, so a shorter result means an entry this
            // guard cannot read - and "no escaped types" would then describe what it managed to look at
            // rather than the array it was handed.
            if (details.ToTypedArray() is not { } typed || typed.Length != details.Count)
                throw Violation("authorization_details entries", ["an entry that is not a JSON object"]);

            // A missing type is refused rather than skipped. RFC 9396 §2 makes type REQUIRED on every
            // entry, and an entry without one satisfies "not among the escaped" by being unreadable.
            var escapedTypes = typed
                .Select(detail => detail.Type ?? "(no type)")
                .Where(type => !allowed.Contains(type))
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (escapedTypes.Length > 0)
                throw Violation("authorization_details types", escapedTypes);

            return typed.Select(detail => detail.Type!).ToHashSet(StringComparer.Ordinal);
        }
    }

    private static InvalidOperationException Violation(string category, string[] escaped) =>
        new($"The IUserConsentsProvider granted {category} absent from the authorization request: " +
            $"{string.Join(", ", escaped)}. The granted set must be a subset of what the request carried " +
            "(granted ⊆ requested); returning a broader set violates the IUserConsentsProvider " +
            "contract documented on ConsentDefinition and would let the end-user escalate their own grant.");
}
