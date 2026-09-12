// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Indicates that too many verification attempts have been made - by this source, or across the server -
/// and names how long before another will be entertained.
/// </summary>
/// <remarks>
/// Says nothing about the value that was typed, and cannot: it is returned for refusals that counted
/// attempts rather than codes. A host's verification page can show the wait instead of telling somebody
/// their correct code is invalid.
/// </remarks>
/// <param name="RetryAfter">How long before another attempt will be entertained.</param>
public record TooManyUserCodeAttempts(TimeSpan RetryAfter) : UserCodeVerificationResult;
