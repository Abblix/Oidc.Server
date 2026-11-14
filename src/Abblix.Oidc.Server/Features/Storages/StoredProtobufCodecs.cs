// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// The codecs of the values stored as they are, with no domain type mapped onto them: Protocol Buffers messages,
/// and text.
/// </summary>
internal static class StoredProtobufCodecs
{
    /// <summary>
    /// One codec per value stored as itself.
    /// </summary>
    public static readonly IProtobufCodec[] All =
    [
        ProtobufCodecs.Stored(Proto.RevocationCutoff.Parser),
        ProtobufCodecs.Stored(Proto.PollSchedule.Parser),
        ProtobufCodecs.Stored(Proto.RateLimitAttempt.Parser),
        ProtobufCodecs.Stored(Proto.RateLimitGeneration.Parser),
        ProtobufCodecs.Stored(Proto.SessionClient.Parser),
        ProtobufCodecs.Stored(Proto.SessionClientsGeneration.Parser),
        ProtobufCodecs.Stored(Proto.LogoutConfirmation.Parser),
        ProtobufCodecs.Stored(Proto.NonceSecret.Parser),
        ProtobufCodecs.Stored(Proto.ConsumedRequestUri.Parser),
        ProtobufCodecs.Text(),
    ];
}
