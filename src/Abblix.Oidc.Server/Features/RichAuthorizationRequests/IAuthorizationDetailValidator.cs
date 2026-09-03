// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.RichAuthorizationRequests;

/// <summary>
/// Validates a single RFC 9396 authorization_details entry whose <c>type</c> value matches the
/// implementation. Hosts register one implementation per supported <c>type</c> via
/// <see cref="ServiceCollectionExtensions.AddAuthorizationDetailValidator{TValidator}"/>; the
/// composite <see cref="IAuthorizationDetailsPolicy"/> dispatches each request entry to
/// the implementation keyed by the entry's <c>type</c> value.
/// </summary>
/// <remarks>
/// The library ships no concrete implementations of this interface - each authorization-detail
/// type (e.g. <c>payment_initiation</c>, <c>consent</c>, OpenID4VC presentation schemas) demands
/// its own per-type schema and is contributed by the host or a separate package. RFC 9396 section 5
/// requires the AS to refuse any entry whose <c>type</c> is unknown; with zero implementations
/// registered, every RAR-bearing request is rejected with <c>invalid_authorization_details</c>
/// and the server still boots cleanly.
/// </remarks>
public interface IAuthorizationDetailValidator
{
    /// <summary>
    /// The authorization-detail <c>type</c> value this validator handles. Used as the DI key
    /// under which the implementation is registered and looked up at request time.
    /// </summary>
    string Type { get; }

    /// <summary>
    /// Validates a single authorization-detail entry against this validator's per-type schema
    /// and any per-client policy the implementation chooses to enforce.
    /// </summary>
    /// <param name="detail">The entry to validate. Its <see cref="AuthorizationDetail.Type"/>
    /// matches this validator's <see cref="Type"/>; the per-type schema lives in the raw
    /// <see cref="AuthorizationDetail.Json"/> object alongside the RFC 9396 section 2.2
    /// standardised members where applicable.</param>
    /// <param name="client">The client that submitted the request, for policy decisions that
    /// depend on per-client allowlists or registered metadata.</param>
    /// <param name="token">Cancellation token.</param>
    /// <returns>The validated (and possibly normalised) detail on success, or a
    /// <see cref="OidcError"/> describing the rejection reason on
    /// failure. RFC 9396 section 5 makes the protocol-level error code at the wire
    /// <c>invalid_authorization_details</c> regardless of the underlying reason.</returns>
    Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
        AuthorizationDetail detail,
        ClientInfo client,
        CancellationToken token);

    /// <summary>
    /// Validates a single entry as the consent decision left it, which may carry values the server
    /// itself added while the end-user was choosing. Defaults to <see cref="ValidateAsync"/>, so a
    /// type that does not enrich answers the same question in both phases.
    /// </summary>
    /// <remarks>
    /// RFC 9396 section 7.1 says that "Whether enrichment is allowed and specifics of how it works are
    /// necessarily part of the definition of the respective authorization details type", and in this
    /// library the definition of a type is this validator. Its worked example (Figures 16 and 17) is
    /// an <c>account_information</c> entry whose empty arrays are placeholders the server fills with
    /// the identifiers the user picked.
    /// <para>
    /// That shape is one the request-time question may legitimately refuse: RFC 9396 section 5 has the server
    /// reject an entry that "contains fields with invalid values for the authorization details type",
    /// and a type whose definition says the client must not choose the accounts makes a populated
    /// placeholder exactly that. Such a type overrides this member so the consent decision's own
    /// output is accepted, while <see cref="ValidateAsync"/> keeps refusing it from a client.
    /// </para>
    /// <para>
    /// An override MUST still refuse everything <see cref="ValidateAsync"/> refuses, apart from the
    /// fields its type declares enrichable. This is the anti-escalation re-check, and the consent
    /// decision reaching it has often crossed the browser: what the library still guarantees for an
    /// overriding type is only that entries are JSON objects, that their types are known, requested
    /// and on the client's allowlist. Everything inside an entry - an amount, an account, a list of
    /// locations - is guaranteed by this method and by nothing else. An override that returns its
    /// input unconditionally hands a tampered consent decision straight to the issued token.
    /// </para>
    /// <para>
    /// Note what this method is NOT given: the entry the client originally sent, and the end user who
    /// answered. So an enrichable field can be bounded here only by rules that hold on their own - a
    /// ceiling, a format, a per-client limit - and not by comparing the value against the request it
    /// came from. A type whose enrichment needs that comparison has to make it where both sides are in
    /// hand, which today is the consent provider that produced the decision.
    /// </para>
    /// </remarks>
    /// <param name="detail">The granted entry, whose <see cref="AuthorizationDetail.Type"/> matches
    /// this validator's <see cref="Type"/>.</param>
    /// <param name="client">The client the grant is being issued to.</param>
    /// <param name="token">Cancellation token.</param>
    /// <returns>The validated (and possibly normalised) detail on success, or an
    /// <see cref="OidcError"/> describing the rejection. A rejection here means the consent decision
    /// escalated beyond what this type permits, which is a host-side defect rather than a client
    /// error.</returns>
    Task<Result<AuthorizationDetail, OidcError>> ValidateGrantedAsync(
        AuthorizationDetail detail,
        ClientInfo client,
        CancellationToken token)
        => ValidateAsync(detail, client, token);

    /// <summary>
    /// Optional: produces a host-renderable <see cref="AuthorizationDetailDescriptor"/> describing
    /// what consenting to this entry authorises, so the consent UI can render a meaningful screen
    /// instead of a raw JSON dump. Default returns <c>null</c>; hosts that opt out simply fall back
    /// to displaying <see cref="AuthorizationDetail.Json"/>. Validators that override this should
    /// extract the structured payload from <see cref="AuthorizationDetail.Json"/> and project it to
    /// the descriptor's Title / Summary / Details shape.
    /// </summary>
    /// <param name="detail">The entry to describe. Already passed
    /// <see cref="ValidateAsync"/>, so the per-type schema is satisfied.</param>
    /// <param name="client">The requesting client, for descriptions that vary by client metadata
    /// (e.g. branding, locale).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The descriptor on success; <c>null</c> when no structured description is
    /// available and the host should fall back to a JSON-dump rendering.</returns>
    Task<AuthorizationDetailDescriptor?> BuildConsentDescriptorAsync(
        AuthorizationDetail detail,
        ClientInfo client,
        CancellationToken cancellationToken)
        => Task.FromResult<AuthorizationDetailDescriptor?>(null);
}
