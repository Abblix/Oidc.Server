// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Provides extension methods for working with <see cref="Result{TSuccess, TFailure}"/> types.
/// </summary>
public static class ResultExtensions
{
    /// <summary>
    /// Ensures that a value satisfies a specified predicate; otherwise, returns a failure.
    /// </summary>
    /// <typeparam name="TSuccess">The type of the value.</typeparam>
    /// <typeparam name="TFailure">The type of the failure.</typeparam>
    /// <param name="value">The value to validate.</param>
    /// <param name="predicate">The predicate to evaluate.</param>
    /// <param name="failure">The failure to return if the predicate is not satisfied.</param>
    /// <returns>A successful result if the predicate is satisfied; otherwise, a failed result.</returns>
    public static Result<TSuccess, TFailure> Ensure<TSuccess, TFailure>(
        this TSuccess value,
        Func<TSuccess, bool> predicate,
        TFailure failure)
    {
        return predicate(value) ? value : failure;
    }

    /// <summary>
    /// Asynchronously ensures that a value satisfies a specified predicate; otherwise, returns a failure.
    /// </summary>
    /// <typeparam name="TSuccess">The type of the value.</typeparam>
    /// <typeparam name="TFailure">The type of the failure.</typeparam>
    /// <param name="valueTask">The asynchronous task producing the value.</param>
    /// <param name="predicate">The predicate to evaluate.</param>
    /// <param name="failure">The failure to return if the predicate is not satisfied.</param>
    /// <returns>A task representing the successful or failed result.</returns>
    public static async Task<Result<TSuccess, TFailure>> EnsureAsync<TSuccess, TFailure>(
        this Task<TSuccess> valueTask,
        Func<TSuccess, bool> predicate,
        TFailure failure)
    {
        var value = await valueTask;
        return value.Ensure(predicate, failure);
    }

    /// <summary>
    /// Converts a nullable value into a successful result if not null; otherwise, returns a failure.
    /// </summary>
    /// <typeparam name="TSuccess">The type of the value.</typeparam>
    /// <typeparam name="TFailure">The type of the failure.</typeparam>
    /// <param name="value">The nullable value to check.</param>
    /// <param name="failure">The failure to return if the value is null.</param>
    /// <returns>A successful result if the value is not null; otherwise, a failed result.</returns>
    public static Result<TSuccess, TFailure> FailIfNull<TSuccess, TFailure>(
        this TSuccess? value,
        TFailure failure)
    {
        return value is not null ? value : failure;
    }

    /// <summary>
    /// Converts a nullable value into a successful result if not null; otherwise, returns a failure.
    /// </summary>
    /// <typeparam name="TSuccess">The type of the value.</typeparam>
    /// <typeparam name="TFailure">The type of the failure.</typeparam>
    /// <param name="value">The nullable value to check.</param>
    /// <param name="failure">The failure to return if the value is null.</param>
    /// <returns>A successful result if the value is not null; otherwise, a failed result.</returns>
    public static Result<TSuccess, TFailure> FailIfNull<TSuccess, TFailure>(
        this TSuccess? value,
        Func<TFailure> failure)
    {
        return value is not null ? value : failure();
    }

    /// <summary>
    /// Asynchronously converts a nullable value into a successful result if not null; otherwise, returns a failure.
    /// </summary>
    /// <typeparam name="TSuccess">The type of the value.</typeparam>
    /// <typeparam name="TFailure">The type of the failure.</typeparam>
    /// <param name="valueTask">The asynchronous task producing the nullable value.</param>
    /// <param name="failure">The failure to return if the value is null.</param>
    /// <returns>A task representing the successful or failed result.</returns>
    public static async Task<Result<TSuccess, TFailure>> FailIfNullAsync<TSuccess, TFailure>(
        this Task<TSuccess?> valueTask,
        TFailure failure)
    {
        var value = await valueTask;
        return value.FailIfNull(failure);
    }

    /// <summary>
    /// Asynchronously converts a nullable value into a successful result if not null; otherwise, returns a failure.
    /// </summary>
    /// <typeparam name="TSuccess">The type of the value.</typeparam>
    /// <typeparam name="TFailure">The type of the failure.</typeparam>
    /// <param name="valueTask">The asynchronous task producing the nullable value.</param>
    /// <param name="failure">The failure to return if the value is null.</param>
    /// <returns>A task representing the successful or failed result.</returns>
    public static async Task<Result<TSuccess, TFailure>> FailIfNullAsync<TSuccess, TFailure>(
        this Task<TSuccess?> valueTask,
        Func<TFailure> failure)
    {
        var value = await valueTask;
        return value.FailIfNull(failure);
    }

    /// <summary>
    /// Asynchronously binds a result-producing function to the result of a task, if the result is successful.
    /// </summary>
    /// <typeparam name="TSuccess">The type of the original success value.</typeparam>
    /// <typeparam name="TFailure">The type of the failure.</typeparam>
    /// <typeparam name="TNext">The type of the next success value.</typeparam>
    /// <param name="resultTask">The asynchronous task producing a result.</param>
    /// <param name="func">The function to bind if the result is successful.</param>
    /// <returns>A task representing the new result after binding.</returns>
    public static async Task<Result<TNext, TFailure>> BindAsync<TSuccess, TFailure, TNext>(
        this Task<Result<TSuccess, TFailure>> resultTask,
        Func<TSuccess, Task<Result<TNext, TFailure>>> func)
    {
        var result = await resultTask;
        return await result.BindAsync(func);
    }

    /// <summary>
    /// Binds a synchronous result-producing function to the result of a task, if the result is successful.
    /// </summary>
    /// <typeparam name="TSuccess">The type of the original success value.</typeparam>
    /// <typeparam name="TFailure">The type of the failure.</typeparam>
    /// <typeparam name="TNext">The type of the next success value.</typeparam>
    /// <param name="resultTask">The asynchronous task producing a result.</param>
    /// <param name="func">The synchronous function to bind if the result is successful.</param>
    /// <returns>A task representing the new result after binding.</returns>
    public static async Task<Result<TNext, TFailure>> Bind<TSuccess, TFailure, TNext>(
        this Task<Result<TSuccess, TFailure>> resultTask,
        Func<TSuccess, Result<TNext, TFailure>> func)
    {
        var result = await resultTask;
        return result.Bind(func);
    }

    /// <summary>
    /// Asynchronously maps a successful result to another type.
    /// </summary>
    /// <typeparam name="TSuccess">The type of the original success value.</typeparam>
    /// <typeparam name="TFailure">The type of the failure.</typeparam>
    /// <typeparam name="TNext">The type to map the success value to.</typeparam>
    /// <param name="resultTask">The asynchronous task producing a result.</param>
    /// <param name="onSuccess">The asynchronous mapping function.</param>
    /// <returns>A task representing the new result with the mapped success value.</returns>
    public static async Task<Result<TNext, TFailure>> MapSuccessAsync<TSuccess, TFailure, TNext>(
        this Task<Result<TSuccess, TFailure>> resultTask,
        Func<TSuccess, Task<TNext>> onSuccess)
    {
        var result = await resultTask;
        return await result.MapSuccessAsync(onSuccess);
    }
}
