// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.RichAuthorizationRequests;

/// <summary>
/// Single request-time entry point for the RFC 9396 authorization_details policy: per-client
/// allowlist (§5.1) plus per-type composite dispatch (§5). Endpoint-side adapters delegate
/// here so /authorize, /par, CIBA and device-flow share one policy source.
/// </summary>
/// <remarks>
/// Registered unconditionally by <see cref="ServiceCollectionExtensions.AddRichAuthorizationRequests"/>
/// so the server boots cleanly with zero <see cref="IAuthorizationDetailValidator"/>
/// implementations registered. Per RFC 9396 §5 (the AS MUST refuse unknown types), an empty
/// registry rejects every RAR-bearing request - this is conformance-mandatory, not a
/// configurable policy.
/// </remarks>
public interface IAuthorizationDetailsPolicy
{
    /// <summary>
    /// Full RFC 9396 §5 + §5.1 request-time validation entry point. Takes the raw
    /// authorization_details array as it landed on the wire, applies the per-client
    /// allowlist, dispatches each typed entry to its keyed
    /// <see cref="IAuthorizationDetailValidator"/>, and returns the validated raw array
    /// for the pipeline to forward.
    /// </summary>
    /// <remarks>
    /// The returned <see cref="JsonArray"/> reflects the post-validation set: when per-type
    /// validators leave their inputs untouched it is byte-equivalent to the input, but when
    /// a validator narrows / extends per RFC 9396 §5 (e.g. a consent-UI slider, an AS-policy
    /// cap, or canonicalisation), the mutation surfaces here and the pipeline forwards the
    /// post-validation shape into <c>AuthorizationContext</c> - token emission reflects what
    /// was actually granted, not the original request.
    /// </remarks>
    /// <param name="raw">The raw <c>authorization_details</c> array off the wire, or
    /// <c>null</c> / empty when the request did not carry one.</param>
    /// <param name="client">The authenticated client; <see cref="ClientInfo.AuthorizationDetailsTypes"/>
    /// drives the allowlist branch.</param>
    /// <param name="token">Cancellation token forwarded to per-type validators.</param>
    /// <returns>
    /// On success - the raw <see cref="JsonArray"/> that survived validation (or <c>null</c>
    /// when the input was null / empty / contained no typed entries - there is nothing to
    /// forward in that case). On failure - a fully-formed <see cref="OidcError"/> with
    /// <c>error = invalid_authorization_details</c> (RFC 9396 §5) and the rejection
    /// description; the endpoint adapter forwards it as-is when its error type is
    /// <see cref="OidcError"/>, or re-wraps the description otherwise.
    /// </returns>
    Task<Result<JsonArray?, OidcError>> ApplyAsync(
        JsonArray? raw,
        ClientInfo client,
        CancellationToken token);
}
