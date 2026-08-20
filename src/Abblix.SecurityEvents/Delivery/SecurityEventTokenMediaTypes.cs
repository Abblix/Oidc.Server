// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
    /// two the same name; composing the long form from the short one keeps that a fact rather
    /// than a coincidence of two literals.
    /// </summary>
    public const string SecurityEventToken = "application/" + Abblix.SecurityEvents.SecurityEventToken.TokenType;
}
