// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Utils;

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
}
