// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// A service key together with the lifecycle metadata that lives AROUND it, never on it - the
/// <see cref="JsonWebKey"/> stays a pure JOSE / RFC 7517 model. This is the unit a persistent store saves
/// at generation and the read seam gates by time; the durable backend and the rotation that advances
/// <see cref="Status"/> ship separately.
/// </summary>
/// <param name="Key">The key itself. Its <c>use</c> is the standard JOSE member on the key; secret material
/// is present for a local key and absent for an external one (whose private half lives with a custodian).</param>
/// <param name="Status">The lifecycle state; see <see cref="KeyLifecycleStatus"/>.</param>
/// <param name="NotBefore">When the key becomes eligible to sign.</param>
/// <param name="NotAfter">When the key stops signing. After this the key still verifies published tokens
/// until <see cref="DeleteAfter"/>.</param>
/// <param name="DeleteAfter">When the key may be removed from publication entirely. It is
/// <see cref="NotAfter"/> plus the maximum lifetime of any token the key could have signed, so no live
/// token can still reference it.</param>
public sealed record AuthServiceKeyDescriptor(
    JsonWebKey Key,
    KeyLifecycleStatus Status,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    DateTimeOffset DeleteAfter);
