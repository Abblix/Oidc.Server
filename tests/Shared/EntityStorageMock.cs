// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

// Spelled out rather than left to ImplicitUsings, because this file is compiled into suites that do not enable it.
using System;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.Storages;
using Moq;

namespace Abblix.Tests.Shared;

/// <summary>
/// A mock of the entity storage that hands every call to a real storage underneath, so a test changes only the
/// one call it is about with a later <c>Setup</c> of its own, which Moq answers before the forwarding one.
/// </summary>
/// <remarks>
/// Strict, so a member the storage gains later and nobody forwards here fails every test that reaches it with
/// an exception, rather than answering a completed <c>false</c> or <c>null</c> the way a loose mock would, which
/// reads to the code under test as a real answer. The member list below is therefore the one place a new
/// member of <see cref="IEntityStorage"/> is added for the test suites.
/// <para>
/// The members taking a type argument are set up with <see cref="It.IsAnyType"/>, so a test overriding one of
/// them answers through an <see cref="InvocationFunc"/>; <see cref="Before"/> and <see cref="After"/> build the
/// ones that run a step around the forwarded call and still return the task type the caller expects.
/// </para>
/// </remarks>
public static class EntityStorageMock
{
    private static readonly MethodInfo AroundOfResult = typeof(EntityStorageMock)
        .GetMethod(nameof(AroundAsync), BindingFlags.NonPublic | BindingFlags.Static)!;

    /// <summary>
    /// A strict mock forwarding every member of the storage to <paramref name="inner"/>.
    /// </summary>
    /// <param name="inner">The storage the calls reach when a test has not set them up otherwise.</param>
    public static Mock<IEntityStorage> Over(IEntityStorage inner)
    {
        var mock = new Mock<IEntityStorage>(MockBehavior.Strict);
        var forward = new InvocationFunc(invocation => Forward(inner, invocation));

        mock.Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<CancellationToken?>()))
            .Returns(forward);

        mock.Setup(s => s.GetAsync<It.IsAnyType>(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken?>()))
            .Returns(forward);

        mock.Setup(s => s.TrySetIfAbsentAsync(
                It.IsAny<string>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<CancellationToken?>()))
            .Returns(forward);

        mock.Setup(s => s.TryReplaceAsync(
                It.IsAny<string>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<CancellationToken?>()))
            .Returns(forward);

        mock.Setup(s => s.TryExtendAsync(It.IsAny<string>(), It.IsAny<StorageOptions>(), It.IsAny<CancellationToken?>()))
            .Returns(forward);

        mock.Setup(s => s.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken?>()))
            .Returns(forward);

        return mock;
    }

    /// <summary>
    /// An answer that runs <paramref name="step"/> and then makes the call on <paramref name="inner"/>.
    /// </summary>
    /// <param name="inner">The storage the call is made on.</param>
    /// <param name="step">What happens first, handed the call it comes before.</param>
    public static InvocationFunc Before(IEntityStorage inner, Func<IInvocation, Task> step)
        => new(invocation => Around(invocation, async () =>
        {
            await step(invocation);
            return await ResultOf(invocation, Forward(inner, invocation));
        }));

    /// <summary>
    /// An answer that makes the call on <paramref name="inner"/> and then runs <paramref name="step"/> before the
    /// caller sees the result.
    /// </summary>
    /// <param name="inner">The storage the call is made on.</param>
    /// <param name="step">What happens next, handed the call and what it answered.</param>
    public static InvocationFunc After(IEntityStorage inner, Func<IInvocation, object?, Task> step)
        => new(invocation => Around(invocation, async () =>
        {
            var result = await ResultOf(invocation, Forward(inner, invocation));
            await step(invocation, result);
            return result;
        }));

    /// <summary>
    /// Makes the same call on <paramref name="inner"/>: the method Moq reports is the closed one the code under
    /// test called, so a generic member reaches the inner storage with the type it was called with.
    /// </summary>
    private static object Forward(IEntityStorage inner, IInvocation invocation)
    {
        try
        {
            return invocation.Method.Invoke(inner, invocation.Arguments.ToArray())!;
        }
        catch (TargetInvocationException exception) when (exception.InnerException is { } thrown)
        {
            ExceptionDispatchInfo.Capture(thrown).Throw();
            throw;
        }
    }

    /// <summary>
    /// The task of the type the called member returns, completing with what <paramref name="body"/> answers.
    /// </summary>
    private static object Around(IInvocation invocation, Func<Task<object?>> body)
    {
        var returnType = invocation.Method.ReturnType;
        if (returnType == typeof(Task))
            return body();

        return AroundOfResult.MakeGenericMethod(returnType.GetGenericArguments()[0]).Invoke(null, [body])!;
    }

    private static async Task<T> AroundAsync<T>(Func<Task<object?>> body) => (T)(await body())!;

    /// <summary>
    /// What a forwarded call answered, read through the member's declared return type, since the task the inner
    /// storage hands back may be of a type that derives from it.
    /// </summary>
    private static async Task<object?> ResultOf(IInvocation invocation, object call)
    {
        var task = (Task)call;
        await task;

        var returnType = invocation.Method.ReturnType;
        return returnType == typeof(Task) ? null : returnType.GetProperty(nameof(Task<object>.Result))!.GetValue(task);
    }
}
