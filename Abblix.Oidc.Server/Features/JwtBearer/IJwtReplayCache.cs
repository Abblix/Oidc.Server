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

namespace Abblix.Oidc.Server.Features.JwtBearer;

/// <summary>
/// Backward-compat alias for <see cref="ReplayPrevention.IJwtReplayCache"/>. The contract is identical;
/// the canonical type now lives in <c>Abblix.Oidc.Server.Features.ReplayPrevention</c> so DPoP and
/// any future consumer can share the same primitive without cross-feature coupling.
/// Update consumers to import the new namespace.
/// </summary>
[Obsolete($"Use {nameof(Features)}.{nameof(ReplayPrevention)}.{nameof(IJwtReplayCache)}. " +
          "The contract is identical and this interface derives from it for backward compatibility.")]
public interface IJwtReplayCache : ReplayPrevention.IJwtReplayCache;
