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

namespace Abblix.Oidc.Server.Features.AuthorizationDetails;

/// <summary>
/// Composite validator for an RFC 9396 authorization_details array. Dispatches each entry to
/// the matching keyed <see cref="IAuthorizationDetailValidator"/> by the entry's <c>type</c>
/// value; an unknown type or a per-type validator failure stops processing and returns the
/// failure. Called from the authorize/PAR endpoint validators in slice #133.
/// </summary>
/// <remarks>
/// Registered unconditionally by <see cref="ServiceCollectionExtensions.AddAuthorizationDetails"/>
/// so the server boots cleanly with zero <see cref="IAuthorizationDetailValidator"/>
/// implementations registered. Per RFC 9396 §5 (the AS MUST refuse unknown types), an empty
/// registry rejects every RAR-bearing request — this is conformance-mandatory, not a
/// configurable policy.
/// </remarks>
public interface IAuthorizationDetailsValidator
{
    /// <summary>
    /// Validates an authorization_details array. Fails on the first unknown <c>type</c> or
    /// per-type validator failure; on success returns the validated (possibly normalised)
    /// array preserving order.
    /// </summary>
    /// <param name="details">The authorization_details array submitted by the client, or an
    /// empty sequence if the request carried no such claim.</param>
    /// <param name="client">The client that submitted the request, threaded into per-type
    /// validators for per-client policy decisions.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The validated array on success, or an
    /// <see cref="AuthorizationDetailValidationError"/> describing the first rejection.</returns>
    Task<Result<IReadOnlyList<AuthorizationDetail>, AuthorizationDetailValidationError>> ValidateAsync(
        IEnumerable<AuthorizationDetail> details,
        ClientInfo client,
        CancellationToken ct);
}
