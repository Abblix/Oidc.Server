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

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.JwtBearer;

/// <summary>
/// Backward-compat shim for <see cref="ReplayPrevention.DistributedJwtReplayCache"/>. The
/// canonical implementation now lives in
/// <c>Abblix.Oidc.Server.Features.ReplayPrevention</c>. This subclass exists so any host
/// code that DI-resolves <see cref="IJwtReplayCache"/> (the deprecated interface) keeps
/// receiving an instance of the same logical type.
/// </summary>
[Obsolete($"Use {nameof(Features)}.{nameof(ReplayPrevention)}.{nameof(DistributedJwtReplayCache)}. " +
          "Behaviour is identical; this type is a backward-compat shim that delegates to " +
          "the canonical implementation.")]
public sealed class DistributedJwtReplayCache(
    ILogger<ReplayPrevention.DistributedJwtReplayCache> logger,
    IDistributedCache cache,
    IOptionsMonitor<OidcOptions> options,
    TimeProvider timeProvider)
    : ReplayPrevention.DistributedJwtReplayCache(logger, cache, options, timeProvider), IJwtReplayCache;
