// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Storages;

partial class CompositeBinarySerializer
{
    [LoggerMessage(
        EventId = LogEvents.Misc.CompositeBinarySerializer.ProtobufSerializeFallback,
        Level = LogLevel.Warning,
        Message = "Type {TypeName} is not supported for protobuf serialization, falling back to JSON")]
    private partial void LogProtobufSerializeFallback(Exception ex, string? TypeName);

    [LoggerMessage(
        EventId = LogEvents.Misc.CompositeBinarySerializer.ProtobufDeserializeFallback,
        Level = LogLevel.Warning,
        Message = "Type {TypeName} is not supported for protobuf deserialization, falling back to JSON")]
    private partial void LogProtobufDeserializeFallback(Exception ex, string? TypeName);
}
