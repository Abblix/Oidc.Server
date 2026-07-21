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


namespace Abblix.Oidc.Client.Features.Revocation;

/// <summary>
/// Thrown when a token could not be revoked.
/// </summary>
public sealed class TokenRevocationException : Exception
{
    /// <summary>
    /// Creates the exception for a provider that refused the request.
    /// </summary>
    /// <param name="message">What went wrong.</param>
    /// <param name="error">The <c>error</c> code the provider returned, when it returned one.</param>
    /// <param name="tokenMayStillExist">Whether the token has to be assumed live.</param>
    /// <param name="retryAfter">How long the provider asked the caller to wait, when it said.</param>
    public TokenRevocationException(
        string message,
        string? error = null,
        bool tokenMayStillExist = false,
        TimeSpan? retryAfter = null)
        : base(message)
    {
        Error = error;
        TokenMayStillExist = tokenMayStillExist;
        RetryAfter = retryAfter;
    }

    /// <summary>
    /// Creates the exception for a failure that never reached a protocol answer.
    /// </summary>
    /// <remarks>
    /// The token has to be assumed live: nothing came back to say otherwise.
    /// </remarks>
    public TokenRevocationException(string message, Exception innerException)
        : base(message, innerException)
        => TokenMayStillExist = true;

    /// <summary>
    /// The <c>error</c> code from the provider's response, such as <c>unsupported_token_type</c>.
    /// </summary>
    public string? Error { get; }

    /// <summary>
    /// Whether the caller must go on treating the token as valid.
    /// </summary>
    /// <remarks>
    /// RFC 7009 section 2.2.1: "If the server responds with HTTP status code 503, the client must assume the
    /// token still exists and may retry after a reasonable delay." The distinction is the whole point of
    /// revoking on logout - a caller that treats every failure as final leaves a live token behind believing
    /// it is dead.
    /// </remarks>
    public bool TokenMayStillExist { get; }

    /// <summary>
    /// How long the provider asked the caller to wait before retrying, from the <c>Retry-After</c> header.
    /// </summary>
    /// <remarks>
    /// RFC 7009 section 2.2.1: "The server may include a 'Retry-After' header in the response to indicate how
    /// long the service is expected to be unavailable."
    /// </remarks>
    public TimeSpan? RetryAfter { get; }
}
