// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The clients an issuer's settings configure, built once for each version of the settings, and whether the
/// registrations under their ids have been dropped yet.
/// </summary>
/// <param name="clients">The configured clients by id.</param>
internal sealed class ConfiguredClients(Dictionary<string, ClientInfo> clients)
{
    private Task? _evicted;

    // Set while the runs keep failing, so a failure is reported once while it stays so rather than on every reading
    private int _failing;

    /// <summary>
    /// The configured clients by id.
    /// </summary>
    public Dictionary<string, ClientInfo> Clients { get; } = clients;

    /// <summary>
    /// Whether the registrations under these clients' ids have been dropped.
    /// </summary>
    public bool Evicted => Volatile.Read(ref _evicted) is { IsCompletedSuccessfully: true };

    /// <summary>
    /// Runs <paramref name="evict"/> once for these clients however many readers ask at once, and again after a run
    /// that failed, so a store that could not be reached once is asked again by the next reading rather than never.
    /// </summary>
    /// <param name="evict">Drops the registrations; it starts on the caller's thread, while the request is alive.
    /// </param>
    /// <param name="failed">Reports a failure, the first of a run of failures.</param>
    public Task EvictedAsync(Func<Task> evict, Action<Exception> failed)
    {
        while (true)
        {
            var held = Volatile.Read(ref _evicted);
            if (held is { IsFaulted: false, IsCanceled: false })
                return held;

            var run = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            if (Interlocked.CompareExchange(ref _evicted, run.Task, held) != held)
                continue;

            _ = RunAsync(evict, failed, run);
            return run.Task;
        }
    }

    private async Task RunAsync(Func<Task> evict, Action<Exception> failed, TaskCompletionSource run)
    {
        try
        {
            await evict();
            Volatile.Write(ref _failing, 0);
            run.SetResult();
        }
        catch (Exception exception)
        {
            if (Interlocked.Exchange(ref _failing, 1) == 0)
                failed(exception);

            run.SetException(exception);

            // Reported above and retried by the next reading, so it is not left for the unobserved-task handler
            _ = run.Task.Exception;
        }
    }
}
