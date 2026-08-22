// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Vault;

/// <summary>
/// Verdict of a renewal attempt: the status, and the renewed lease when there is one.
/// </summary>
/// <param name="Status">How the attempt ended.</param>
/// <param name="Lease">The renewed lease when <paramref name="Status"/> is <see cref="RenewStatus.Renewed"/>.</param>
internal readonly record struct RenewResult(RenewStatus Status, TokenLease? Lease);
