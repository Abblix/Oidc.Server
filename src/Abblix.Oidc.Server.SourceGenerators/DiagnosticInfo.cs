// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.CodeAnalysis;

namespace Abblix.Oidc.Server.SourceGenerators;

/// <summary>
/// A diagnostic captured as equatable data; <see cref="Diagnostic"/> itself holds non-equatable
/// state and would defeat pipeline caching.
/// </summary>
internal sealed record DiagnosticInfo(DiagnosticDescriptor Descriptor, LocationInfo Location, params object?[] Arguments)
{
    public Diagnostic ToDiagnostic() => Diagnostic.Create(Descriptor, Location.ToLocation(), Arguments);

    public bool Equals(DiagnosticInfo? other)
        => other != null &&
           Descriptor.Id == other.Descriptor.Id &&
           Location == other.Location &&
           Arguments.SequenceEqual(other.Arguments);

    public override int GetHashCode()
    {
        var hashCode = Descriptor.Id.GetHashCode();
        hashCode = unchecked(hashCode * 31 + Location.GetHashCode());

        foreach (var argument in Arguments)
        {
            hashCode = unchecked(hashCode * 31 + (argument?.GetHashCode() ?? 0));
        }

        return hashCode;
    }
}