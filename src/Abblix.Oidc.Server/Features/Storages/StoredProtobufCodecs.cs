// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// The codecs of the Protocol Buffers messages stored as they are, with no domain type mapped onto them.
/// </summary>
internal static class StoredProtobufCodecs
{
    /// <summary>
    /// One codec per message stored as itself.
    /// </summary>
    public static readonly ProtobufCodec[] All =
    [
        ProtobufCodec.Stored(Proto.RevocationCutoff.Parser),
        ProtobufCodec.Stored(Proto.PollSchedule.Parser),
        ProtobufCodec.Stored(Proto.RateLimitAttempt.Parser),
        ProtobufCodec.Stored(Proto.RateLimitGeneration.Parser),
        ProtobufCodec.Stored(Proto.SessionClient.Parser),
        ProtobufCodec.Stored(Proto.SessionClientsGeneration.Parser),
        ProtobufCodec.Stored(Proto.LogoutConfirmation.Parser),
        ProtobufCodec.Stored(Proto.NonceSecret.Parser),
        ProtobufCodec.Stored(Proto.ConsumedRequestUri.Parser),
    ];
}
