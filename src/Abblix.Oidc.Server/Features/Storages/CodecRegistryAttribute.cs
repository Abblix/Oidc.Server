// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Marks a field holding codecs <see cref="ProtobufSerializer"/> serves stored types with.
/// </summary>
/// <remarks>
/// ABX1009 counts a codec only when it is built in the initializer of a field carrying this mark, so a codec built
/// anywhere the serializer does not look is not taken for one it uses.
/// </remarks>
[AttributeUsage(AttributeTargets.Field, Inherited = false)]
internal sealed class CodecRegistryAttribute : Attribute;
