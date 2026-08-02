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

namespace Abblix.SecurityEvents.Delivery;

/// <summary>
/// The media type a SET travels under (RFC 8417 Section 7.3). RFC 8935 Section 2.1 requires it as
/// the Content-Type of a push transmission request; everything else in delivery -
/// poll requests, poll responses, error bodies - is plain application/json, for which the
/// framework's own constant serves.
/// </summary>
public static class SecurityEventTokenMediaTypes
{
    /// <summary>
    /// "application/secevent+jwt": the full media type, as an HTTP header carries it. The token's
    /// "typ" header uses the short spelling instead - that value lives on
    /// <see cref="SecurityEventToken.TokenType"/>, and RFC 7515 Section 4.1.9 is what makes the
    /// two the same name.
    /// </summary>
    public const string SecurityEventToken = "application/secevent+jwt";
}
