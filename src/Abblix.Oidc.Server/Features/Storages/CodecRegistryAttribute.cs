// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Marks the field <see cref="ProtobufSerializer"/> takes the codecs of stored types from.
/// </summary>
/// <remarks>
/// ABX1009 counts a codec only when it is built in the initializer of the field carrying this mark, or of a field or
/// auto-property that initializer reads, so a codec built where the serializer does not look, a registry nobody wired
/// to it included, is not taken for one it uses. A member read counts whole, even where the initializer filters some
/// of its codecs out. ABX1011 refuses the mark on more than one field.
/// </remarks>
[AttributeUsage(AttributeTargets.Field, Inherited = false)]
internal sealed class CodecRegistryAttribute : Attribute;
