// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.AuthorizationDetails;

/// <summary>
/// Composite validator for an RFC 9396 authorization_details array. Owns both the
/// per-client allowlist check (§5.1) and the per-type dispatch to keyed
/// <see cref="IAuthorizationDetailValidator"/> implementations (§5).
/// </summary>
/// <remarks>
/// Registered unconditionally by <see cref="ServiceCollectionExtensions.AddRichAuthorizationRequests"/>
/// so the server boots cleanly with zero <see cref="IAuthorizationDetailValidator"/>
/// implementations registered. Per RFC 9396 §5 (the AS MUST refuse unknown types), an empty
/// registry rejects every RAR-bearing request — this is conformance-mandatory, not a
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
    /// The returned <see cref="JsonArray"/> is currently always identical to the input
    /// (byte-exact pass-through). The return slot exists so that when the validator
    /// narrow / extend mutation path (RFC 9396 §5) lands, per-type validators can return
    /// a modified detail and the composite reconstructs the raw array from the post-
    /// validation set — the pipeline reads from this return value, not from the original
    /// request, so narrowing surfaces in the issued token without further plumbing.
    /// </remarks>
    /// <param name="raw">The raw <c>authorization_details</c> array off the wire, or
    /// <c>null</c> / empty when the request did not carry one.</param>
    /// <param name="client">The authenticated client; <see cref="ClientInfo.AuthorizationDetailsTypes"/>
    /// drives the allowlist branch.</param>
    /// <param name="token">Cancellation token forwarded to per-type validators.</param>
    /// <returns>
    /// On success — the raw <see cref="JsonArray"/> that survived validation byte-exact (or
    /// <c>null</c> when the input was null / empty / contained no typed entries — there is
    /// nothing to forward in that case). On failure — a fully-formed
    /// <see cref="OidcError"/> with <c>error = invalid_authorization_details</c> (RFC 9396 §5)
    /// and the rejection description; the endpoint adapter forwards it as-is when its
    /// error type is <see cref="OidcError"/>, or re-wraps the description otherwise.
    /// </returns>
    Task<Result<JsonArray?, OidcError>> ApplyAsync(
        JsonArray? raw,
        ClientInfo client,
        CancellationToken token = default);

    /// <summary>
    /// Low-level dispatch of an already-typed authorization_details list to per-type
    /// <see cref="IAuthorizationDetailValidator"/> implementations. Does NOT apply the
    /// per-client allowlist — that's the job of <see cref="ApplyAsync"/>. Exposed for
    /// callers that have already projected and want the per-type validation step alone
    /// (tests, future custom flows).
    /// </summary>
    /// <param name="details">The authorization_details list, post-typed-projection.</param>
    /// <param name="client">The client that submitted the request, threaded into per-type
    /// validators for per-client policy decisions.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The validated list on success, or an
    /// <see cref="AuthorizationDetailValidationError"/> describing the first rejection.</returns>
    Task<Result<IReadOnlyList<AuthorizationDetail>, AuthorizationDetailValidationError>> ValidateAsync(
        IEnumerable<AuthorizationDetail> details,
        ClientInfo client,
        CancellationToken ct);
}
