// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Vault;

/// <summary>
/// What a successful login or renewal hands back: the token and how long its lease runs.
/// </summary>
/// <param name="Token">The client token to present on every request.</param>
/// <param name="LeaseDuration">How long the lease runs from now. Renewal happens well before it ends.</param>
/// <param name="Renewable">
/// Whether the token can be renewed at all. A batch token cannot, and for it the lifecycle skips renewal and
/// simply logs in again before the lease runs out.
/// </param>
internal sealed record TokenLease(string Token, TimeSpan LeaseDuration, bool Renewable);
