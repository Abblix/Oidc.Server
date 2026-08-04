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

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Represents a specific type of validation result for an authorization request that has been deemed invalid.
/// This record details the nature of the validation failure through an error code and description, providing
/// insights into why the request did not pass validation checks. It also includes the redirect URI to guide
/// the client on where to direct the user for further actions if necessary.
/// </summary>
/// <remarks>
/// This is the validator-stage error type, returned by <see cref="IAuthorizationRequestValidator"/> in the
/// failure leg of <see cref="Abblix.Utils.Result{TSuccess,TFailure}"/>. The handler/processor stage wraps it
/// into <see cref="AuthorizationError"/>, which adds the originating <c>Model</c> (needed for polymorphic
/// dispatch through the <see cref="AuthorizationResponse"/> hierarchy) and the optional <c>error_uri</c>.
/// <para>
/// Two parallel error types exist because of the layered architecture: the validator pipeline operates on
/// the generic <see cref="Abblix.Utils.Result{TSuccess,TFailure}"/> envelope and stays free of response-level
/// concerns; the response hierarchy needs <c>Model</c> for state propagation. The cost is duplication of
/// <c>Error</c>, <c>ErrorDescription</c>, <c>ResponseMode</c>, <c>RedirectUri</c> across both types -
/// accepted for the architectural seam.
/// </para>
/// </remarks>
public record AuthorizationRequestValidationError(string Error, string ErrorDescription, Uri? RedirectUri, string ResponseMode)
    : OidcError(Error, ErrorDescription);
