// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Runs each call to the server's entity storage as a stage of the request, and records how long it took into
/// <see cref="OidcMetrics.StorageOperationDuration"/>.
/// </summary>
/// <remarks>
/// Written by hand rather than generated: the storage's methods are generic, which the generated decorators do not
/// take. The measurement is taken whether or not an endpoint's span is open, since a background service's reads load
/// the store as much as a request's.
/// </remarks>
/// <param name="inner">The storage the server uses.</param>
/// <param name="instruments">Records each call into the server's metrics.</param>
internal sealed class MeasuredEntityStorage(IEntityStorage inner, OidcInstruments instruments) : IEntityStorage
{
    /// <inheritdoc />
    public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
        => MeasureAsync(TelemetryStorageOperations.Set, () => inner.SetAsync(key, value, options, token));

    /// <inheritdoc />
    public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
        => MeasureAsync(TelemetryStorageOperations.Get, () => inner.GetAsync<T>(key, removeOnRetrieval, token));

    /// <inheritdoc />
    public Task<bool> TrySetIfAbsentAsync<T>(
        string key, T value, StorageOptions options, CancellationToken? token = null)
        => MeasureAsync(
            TelemetryStorageOperations.SetIfAbsent,
            () => inner.TrySetIfAbsentAsync(key, value, options, token));

    /// <inheritdoc />
    public Task RemoveAsync(string key, CancellationToken? token = null)
        => MeasureAsync(TelemetryStorageOperations.Remove, () => inner.RemoveAsync(key, token));

    private async Task MeasureAsync(string operation, Func<Task> call)
        => await MeasureAsync(operation, async () =>
        {
            await call();
            return true;
        });

    private async Task<TResult> MeasureAsync<TResult>(string operation, Func<Task<TResult>> call)
    {
        var started = Stopwatch.GetTimestamp();
        try
        {
            return await StageObservation.RunAsync(TelemetryStages.Storage, call, StageObservation.NeverRefused);
        }
        finally
        {
            instruments.StorageOperation(operation, Stopwatch.GetElapsedTime(started));
        }
    }
}
