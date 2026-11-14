// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Why a verification attempt was refused by the rate limits, and for how long.
/// </summary>
/// <remarks>
/// <see cref="AboutThisCode"/> is what decides whether the refusal may be shown. Only a value the server
/// issued can have attempts recorded against it, so saying "this one is rate limited" about such a refusal
/// would say that the value is a real code - the disclosure a plain refusal exists to prevent. The
/// per-address cap and the server's budget carry no such information, so they can be named, and a caller
/// refused by them is told how long to wait instead of being shown what a typo shows.
/// </remarks>
/// <param name="RetryAfter">How long before the attempt may be made again.</param>
/// <param name="AboutThisCode">True when the refusal follows from attempts recorded against this very
/// code, which must not be distinguishable from an unknown code.</param>
public record UserCodeRateLimited(TimeSpan RetryAfter, bool AboutThisCode);
