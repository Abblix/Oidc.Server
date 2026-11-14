// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.ExceptionServices;
using StackExchange.Redis;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A Redis connection, or a database, batch or transaction it hands out, that passes every call to a real one and
/// records the keys each database call names, so a test can tell which keys a store read or wrote.
/// </summary>
/// <typeparam name="T">The interface proxied: <see cref="IConnectionMultiplexer"/>, <see cref="IDatabase"/>,
/// <see cref="IBatch"/> or <see cref="ITransaction"/>.</typeparam>
public class RecordingRedisProxy<T> : DispatchProxy where T : class
{
    private T _inner = null!;
    private ConcurrentQueue<(string Method, string Key)> _calls = null!;

    /// <summary>
    /// A connection over <paramref name="inner"/> recording into <paramref name="calls"/> the keys of every call made
    /// on a database it hands out.
    /// </summary>
    public static IConnectionMultiplexer Over(
        IConnectionMultiplexer inner,
        ConcurrentQueue<(string Method, string Key)> calls)
        => RecordingRedisProxy<IConnectionMultiplexer>.Create(inner, calls);

    private static T Create(T inner, ConcurrentQueue<(string Method, string Key)> calls)
    {
        var proxy = Create<T, RecordingRedisProxy<T>>();
        var recording = (RecordingRedisProxy<T>)(object)proxy;
        recording._inner = inner;
        recording._calls = calls;
        return proxy;
    }

    /// <inheritdoc />
    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        var method = targetMethod!;
        if (typeof(IDatabaseAsync).IsAssignableFrom(typeof(T)) && args is not null)
        {
            foreach (var key in args.OfType<RedisKey>().Concat(args.OfType<RedisKey[]>().SelectMany(keys => keys)))
                _calls.Enqueue((method.Name, key.ToString()));
        }

        if (typeof(T) == typeof(IConnectionMultiplexer) && method.Name == nameof(IConnectionMultiplexer.GetDatabase))
            return RecordingRedisProxy<IDatabase>.Create((IDatabase)method.Invoke(_inner, args)!, _calls);

        if (typeof(T) == typeof(IDatabase) && method.Name == nameof(IDatabase.CreateBatch))
            return RecordingRedisProxy<IBatch>.Create((IBatch)method.Invoke(_inner, args)!, _calls);

        if (typeof(T) == typeof(IDatabase) && method.Name == nameof(IDatabase.CreateTransaction))
            return RecordingRedisProxy<ITransaction>.Create((ITransaction)method.Invoke(_inner, args)!, _calls);

        try
        {
            return method.Invoke(_inner, args);
        }
        catch (TargetInvocationException exception)
        {
            ExceptionDispatchInfo.Throw(exception.InnerException!);
            throw;
        }
    }
}
