// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// Decides whether an authorization response came from the server the request was sent to (RFC 9207).
/// </summary>
public interface IResponseIssuerValidator
{
    /// <summary>
    /// Passes silently when the response may be acted on, and throws
    /// <see cref="AuthorizationResponseException"/> when it may not.
    /// </summary>
    /// <param name="issuers">Every issuer identifier the response offers, and the expected one.</param>
    /// <param name="cancellationToken">Cancels the metadata read this may need.</param>
    /// <remarks>
    /// Call this before anything else is done with the response - before the code is redeemed, and
    /// before an error code in it is logged or shown. Until it returns, nothing in the response is
    /// known to have come from the provider.
    /// </remarks>
    Task ValidateAsync(ResponseIssuers issuers, CancellationToken cancellationToken = default);
}
