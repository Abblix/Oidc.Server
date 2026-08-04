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
/// its own per-type schema and is contributed by the host or a separate package. RFC 9396 §5
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
    /// <see cref="AuthorizationDetail.Json"/> object alongside the RFC 9396 §2.2
    /// standardised members where applicable.</param>
    /// <param name="client">The client that submitted the request, for policy decisions that
    /// depend on per-client allowlists or registered metadata.</param>
    /// <param name="token">Cancellation token.</param>
    /// <returns>The validated (and possibly normalised) detail on success, or a
    /// <see cref="OidcError"/> describing the rejection reason on
    /// failure. RFC 9396 §5 makes the protocol-level error code at the wire
    /// <c>invalid_authorization_details</c> regardless of the underlying reason.</returns>
    Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
        AuthorizationDetail detail,
        ClientInfo client,
        CancellationToken token);

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
