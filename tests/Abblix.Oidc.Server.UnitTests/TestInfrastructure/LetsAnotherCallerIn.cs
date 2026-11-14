// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Tests.Shared;
using Moq;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// A storage that, once, runs somebody else's whole cycle in the middle of one caller's operation on a
/// named key.
/// </summary>
/// <remarks>
/// Two callers meeting at one key is a race with many orderings and only one of them loses anything, so a
/// test that fires threads and hopes reproduces the loss sometimes - which is the same as passing for the
/// wrong reason. This produces the ordering that matters, once, deterministically.
/// <para>
/// Which ordering that is depends on what the code under test does with the key. Where it reads a record,
/// changes it and writes it back, the damaging ordering puts the other caller's whole cycle inside the
/// READ: the second writer finishes before the first one writes, and its change is overwritten.
/// Where each event instead claims a key of its own, the ordering to drive is inside the CLAIM: the other
/// caller arrives once this one has taken its key and must therefore be given another.
/// </para>
/// <para>
/// Shared rather than nested in one suite, because every flow that meets another caller at one key needs
/// the same orderings, and a second copy is a second set of semantics to keep in step.
/// </para>
/// <para>
/// Each hook is armed once and disarmed on use, so the other caller's own operations on the same key do
/// not recurse.
/// </para>
/// </remarks>
public sealed class LetsAnotherCallerIn
{
    private readonly string _watched;
    private Func<Task>? _onRead;
    private Func<Task>? _onClaim;
    private Func<Task>? _onRemoval;

    /// <summary>
    /// A storage forwarding every call to <paramref name="inner"/>, with the hooks below armed on
    /// <paramref name="watched"/>.
    /// </summary>
    /// <param name="inner">The storage every call is forwarded to.</param>
    /// <param name="watched">The key whose operations let the other caller in.</param>
    public LetsAnotherCallerIn(IEntityStorage inner, string watched)
    {
        _watched = watched;
        var mock = EntityStorageMock.Over(inner);

        mock.Setup(s => s.GetAsync<It.IsAnyType>(_watched, It.IsAny<bool>(), It.IsAny<CancellationToken?>()))
            .Returns(EntityStorageMock.After(inner, (_, _) => RunOnce(ref _onRead)));

        mock.Setup(s => s.TrySetIfAbsentAsync(
                _watched,
                It.IsAny<It.IsAnyType>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<CancellationToken?>()))
            .Returns(EntityStorageMock.After(inner, (_, _) => RunOnce(ref _onClaim)));

        mock.Setup(s => s.RemoveAsync(_watched, It.IsAny<CancellationToken?>()))
            .Returns(EntityStorageMock.Before(inner, _ => RunOnce(ref _onRemoval)));

        Storage = mock.Object;
    }

    /// <summary>
    /// The storage to hand the code under test.
    /// </summary>
    public IEntityStorage Storage { get; }

    /// <summary>
    /// Arms the interleaving for a read-modify-write: the next read of the watched key runs this, once,
    /// before answering.
    /// </summary>
    public void OnNextReadOf(Func<Task> other) => _onRead = other;

    /// <summary>
    /// Arms the interleaving for claiming: the next claim of the watched key runs this, once, after the
    /// claim has been decided and before its caller continues.
    /// </summary>
    public void OnNextClaimOf(Func<Task> other) => _onClaim = other;

    /// <summary>
    /// Arms the interleaving for a caller that clears several keys: the next removal of the watched key
    /// runs this, once, BEFORE the removal, which is where a caller clearing a range decided how far to go.
    /// </summary>
    public void OnNextRemovalOf(Func<Task> other) => _onRemoval = other;

    private static Task RunOnce(ref Func<Task>? hook)
        => Interlocked.Exchange(ref hook, null) is { } other ? other() : Task.CompletedTask;
}
