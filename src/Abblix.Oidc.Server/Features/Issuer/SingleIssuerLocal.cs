// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// The value of the one issuer a deployment without multi-tenancy serves.
/// </summary>
internal sealed class SingleIssuerLocal<T> : IIssuerLocal<T> where T : class
{
    private Built? _built;

    /// <inheritdoc />
    /// <remarks>
    /// Of two callers building at once, the one that stores its value first wins and the other takes that value,
    /// so what either writes into it is kept.
    /// </remarks>
    public T GetOrCreate(object? source, Func<T> create)
    {
        while (true)
        {
            var built = Volatile.Read(ref _built);
            if (built is not null && ReferenceEquals(built.Source, source))
                return built.Value;

            var fresh = new Built(source, create());
            if (ReferenceEquals(Interlocked.CompareExchange(ref _built, fresh, built), built))
                return fresh.Value;
        }
    }

    private sealed class Built(object? source, T value)
    {
        public object? Source { get; } = source;
        public T Value { get; } = value;
    }
}
