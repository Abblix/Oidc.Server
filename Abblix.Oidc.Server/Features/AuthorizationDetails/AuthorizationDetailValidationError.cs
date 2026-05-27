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

namespace Abblix.Oidc.Server.Features.AuthorizationDetails;

/// <summary>
/// Failure result for RFC 9396 authorization_details validation. Carried as the failure
/// value of <see cref="Abblix.Utils.Result{TSuccess, TFailure}"/> returned by
/// <see cref="IAuthorizationDetailValidator.ValidateAsync"/> and
/// <see cref="IAuthorizationDetailsValidator.ValidateAsync"/>.
/// </summary>
/// <param name="Description">Human-readable description of the rejection cause. Surface
/// into the <c>error_description</c> field of the protocol-level
/// <c>invalid_authorization_details</c> error response per RFC 9396 §4.</param>
/// <remarks>
/// The protocol-level error code at the wire is always <c>invalid_authorization_details</c>
/// per RFC 9396 §5 (the AS MUST refuse). This type carries only the human-readable
/// rejection reason; conversion to a protocol-level <see cref="Abblix.Oidc.Server.Common.OidcError"/>
/// happens at the endpoint integration layer (slice #133).
/// </remarks>
public record AuthorizationDetailValidationError(string Description);
