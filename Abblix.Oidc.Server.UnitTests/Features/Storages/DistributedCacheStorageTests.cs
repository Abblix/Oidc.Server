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

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Caching.Distributed;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// Unit tests for <see cref="DistributedCacheStorage"/> verifying distributed cache
/// operations with serialization support.
/// </summary>
public class DistributedCacheStorageTests
{
    private readonly Mock<IDistributedCache> _cache;
    private readonly Mock<IBinarySerializer> _serializer;
    private readonly DistributedCacheStorage _storage;

    public DistributedCacheStorageTests()
    {
        _cache = new Mock<IDistributedCache>(MockBehavior.Strict);
        _serializer = new Mock<IBinarySerializer>(MockBehavior.Strict);
        _storage = new DistributedCacheStorage(_cache.Object, _serializer.Object);
    }

    private class TestData
    {
        public string Value { get; set; } = string.Empty;
        public int Number { get; set; }
    }

    private static TestData CreateTestData(string value = "test", int number = 42)
        => new() { Value = value, Number = number };

    private static StorageOptions CreateStorageOptions(
        DateTimeOffset? absoluteExpiration = null,
        TimeSpan? absoluteExpirationRelativeToNow = null,
        TimeSpan? slidingExpiration = null)
        => new()
        {
            AbsoluteExpiration = absoluteExpiration,
            AbsoluteExpirationRelativeToNow = absoluteExpirationRelativeToNow,
            SlidingExpiration = slidingExpiration
        };

    /// <summary>
    /// Verifies that SetAsync serializes the value using the binary serializer.
    /// Serialization is required to store objects in distributed cache as byte arrays.
    /// </summary>
    [Fact]
    public async Task SetAsync_ShouldSerializeValue()
    {
        // Arrange
        var key = "test_key";
        var value = CreateTestData();
        var options = CreateStorageOptions();
        var serializedBytes = new byte[] { 1, 2, 3, 4 };

        _serializer
            .Setup(s => s.Serialize(value))
            .Returns(serializedBytes);

        _cache
            .Setup(c => c.SetAsync(
                key,
                serializedBytes,
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        await _storage.SetAsync(key, value, options);

        // Assert
        _serializer.Verify(s => s.Serialize(value), Times.Once);
    }

    /// <summary>
    /// Verifies that SetAsync calls cache.SetAsync with serialized bytes.
    /// The distributed cache stores data as byte arrays.
    /// </summary>
    [Fact]
    public async Task SetAsync_ShouldCallCacheSetAsync()
    {
        // Arrange
        var key = "test_key";
        var value = CreateTestData();
        var options = CreateStorageOptions();
        var serializedBytes = new byte[] { 1, 2, 3, 4 };

        _serializer
            .Setup(s => s.Serialize(value))
            .Returns(serializedBytes);

        _cache
            .Setup(c => c.SetAsync(
                key,
                serializedBytes,
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        await _storage.SetAsync(key, value, options);

        // Assert
        _cache.Verify(
            c => c.SetAsync(
                key,
                serializedBytes,
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that SetAsync maps StorageOptions to DistributedCacheEntryOptions.
    /// Storage options must be translated to the distributed cache format.
    /// </summary>
    [Fact]
    public async Task SetAsync_ShouldMapStorageOptionsToDistributedCacheOptions()
    {
        // Arrange
        var key = "test_key";
        var value = CreateTestData();
        var absoluteExpiration = DateTimeOffset.UtcNow.AddHours(1);
        var relativeExpiration = TimeSpan.FromMinutes(30);
        var slidingExpiration = TimeSpan.FromMinutes(10);
        var options = CreateStorageOptions(
            absoluteExpiration: absoluteExpiration,
            absoluteExpirationRelativeToNow: relativeExpiration,
            slidingExpiration: slidingExpiration);
        DistributedCacheEntryOptions? capturedOptions = null;

        _serializer
            .Setup(s => s.Serialize(value))
            .Returns([1, 2, 3]);

        _cache
            .Setup(c => c.SetAsync(
                It.IsAny<string>(),
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, byte[], DistributedCacheEntryOptions, CancellationToken>(
                (_, _, options, _) => capturedOptions = options)
            .Returns(Task.CompletedTask);

        // Act
        await _storage.SetAsync(key, value, options);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.Equal(absoluteExpiration, capturedOptions!.AbsoluteExpiration);
        Assert.Equal(relativeExpiration, capturedOptions.AbsoluteExpirationRelativeToNow);
        Assert.Equal(slidingExpiration, capturedOptions.SlidingExpiration);
    }

    /// <summary>
    /// Verifies that SetAsync correctly maps AbsoluteExpiration property.
    /// AbsoluteExpiration sets a fixed expiration time for cached entries.
    /// </summary>
    [Fact]
    public async Task SetAsync_ShouldMapAbsoluteExpiration()
    {
        // Arrange
        var key = "test_key";
        var value = CreateTestData();
        var absoluteExpiration = DateTimeOffset.UtcNow.AddDays(1);
        var options = CreateStorageOptions(absoluteExpiration: absoluteExpiration);
        DistributedCacheEntryOptions? capturedOptions = null;

        _serializer
            .Setup(s => s.Serialize(value))
            .Returns([1, 2, 3]);

        _cache
            .Setup(c => c.SetAsync(
                It.IsAny<string>(),
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, byte[], DistributedCacheEntryOptions, CancellationToken>(
                (_, _, options, _) => capturedOptions = options)
            .Returns(Task.CompletedTask);

        // Act
        await _storage.SetAsync(key, value, options);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.Equal(absoluteExpiration, capturedOptions!.AbsoluteExpiration);
    }

    /// <summary>
    /// Verifies that SetAsync correctly maps AbsoluteExpirationRelativeToNow property.
    /// Relative expiration sets expiration time relative to when the entry is stored.
    /// </summary>
    [Fact]
    public async Task SetAsync_ShouldMapAbsoluteExpirationRelativeToNow()
    {
        // Arrange
        var key = "test_key";
        var value = CreateTestData();
        var relativeExpiration = TimeSpan.FromMinutes(45);
        var options = CreateStorageOptions(absoluteExpirationRelativeToNow: relativeExpiration);
        DistributedCacheEntryOptions? capturedOptions = null;

        _serializer
            .Setup(s => s.Serialize(value))
            .Returns([1, 2, 3]);

        _cache
            .Setup(c => c.SetAsync(
                It.IsAny<string>(),
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, byte[], DistributedCacheEntryOptions, CancellationToken>(
                (_, _, options, _) => capturedOptions = options)
            .Returns(Task.CompletedTask);

        // Act
        await _storage.SetAsync(key, value, options);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.Equal(relativeExpiration, capturedOptions!.AbsoluteExpirationRelativeToNow);
    }

    /// <summary>
    /// Verifies that SetAsync correctly maps SlidingExpiration property.
    /// Sliding expiration extends expiration time each time the entry is accessed.
    /// </summary>
    [Fact]
    public async Task SetAsync_ShouldMapSlidingExpiration()
    {
        // Arrange
        var key = "test_key";
        var value = CreateTestData();
        var slidingExpiration = TimeSpan.FromMinutes(20);
        var options = CreateStorageOptions(slidingExpiration: slidingExpiration);
        DistributedCacheEntryOptions? capturedOptions = null;

        _serializer
            .Setup(s => s.Serialize(value))
            .Returns([1, 2, 3]);

        _cache
            .Setup(c => c.SetAsync(
                It.IsAny<string>(),
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, byte[], DistributedCacheEntryOptions, CancellationToken>(
                (_, _, options, _) => capturedOptions = options)
            .Returns(Task.CompletedTask);

        // Act
        await _storage.SetAsync(key, value, options);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.Equal(slidingExpiration, capturedOptions!.SlidingExpiration);
    }

    /// <summary>
    /// Verifies that SetAsync throws ArgumentNullException for null key.
    /// Keys are required to identify cache entries.
    /// </summary>
    [Fact]
    public async Task SetAsync_WithNullKey_ShouldThrowArgumentNullException()
    {
        // Arrange
        var value = CreateTestData();
        var options = CreateStorageOptions();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await _storage.SetAsync(null!, value, options));
    }

    /// <summary>
    /// Verifies that SetAsync uses CancellationToken.None when token is null.
    /// Default cancellation token ensures the operation can still be tracked.
    /// </summary>
    [Fact]
    public async Task SetAsync_WithNullToken_ShouldUseCancellationTokenNone()
    {
        // Arrange
        var key = "test_key";
        var value = CreateTestData();
        var options = CreateStorageOptions();
        CancellationToken capturedToken = default;

        _serializer
            .Setup(s => s.Serialize(value))
            .Returns([1, 2, 3]);

        _cache
            .Setup(c => c.SetAsync(
                It.IsAny<string>(),
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, byte[], DistributedCacheEntryOptions, CancellationToken>(
                (_, _, _, token) => capturedToken = token)
            .Returns(Task.CompletedTask);

        // Act
        await _storage.SetAsync(key, value, options, token: null);

        // Assert
        Assert.Equal(CancellationToken.None, capturedToken);
    }

    /// <summary>
    /// Verifies that SetAsync passes provided cancellation token to cache.
    /// Cancellation tokens allow operations to be cancelled when needed.
    /// </summary>
    [Fact]
    public async Task SetAsync_WithProvidedToken_ShouldPassTokenToCache()
    {
        // Arrange
        var key = "test_key";
        var value = CreateTestData();
        var options = CreateStorageOptions();
        var cancellationTokenSource = new CancellationTokenSource();
        var expectedToken = cancellationTokenSource.Token;
        CancellationToken capturedToken = default;

        _serializer
            .Setup(s => s.Serialize(value))
            .Returns([1, 2, 3]);

        _cache
            .Setup(c => c.SetAsync(
                It.IsAny<string>(),
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, byte[], DistributedCacheEntryOptions, CancellationToken>(
                (_, _, _, token) => capturedToken = token)
            .Returns(Task.CompletedTask);

        // Act
        await _storage.SetAsync(key, value, options, expectedToken);

        // Assert
        Assert.Equal(expectedToken, capturedToken);
    }

    /// <summary>
    /// Verifies that GetAsync returns deserialized object for valid key.
    /// Retrieval should deserialize stored bytes back to the original object type.
    /// </summary>
    [Fact]
    public async Task GetAsync_WithValidKey_ShouldReturnDeserializedObject()
    {
        // Arrange
        var key = "test_key";
        var expectedData = CreateTestData();
        var serializedBytes = new byte[] { 1, 2, 3, 4 };

        _cache
            .Setup(c => c.GetAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync(serializedBytes);

        _serializer
            .Setup(s => s.Deserialize<TestData>(serializedBytes))
            .Returns(expectedData);

        // Act
        var result = await _storage.GetAsync<TestData>(key, removeOnRetrieval: false);

        // Assert
        Assert.Same(expectedData, result);
    }

    /// <summary>
    /// Verifies that GetAsync returns default for non-existent key.
    /// When cache returns null, the method should return the default value for the type.
    /// </summary>
    [Fact]
    public async Task GetAsync_WithNonExistentKey_ShouldReturnDefault()
    {
        // Arrange
        var key = "non_existent_key";

        _cache
            .Setup(c => c.GetAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);

        // Act
        var result = await _storage.GetAsync<TestData>(key, removeOnRetrieval: false);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that GetAsync calls cache.GetAsync once.
    /// Cache should be queried exactly once per retrieval operation.
    /// </summary>
    [Fact]
    public async Task GetAsync_ShouldCallCacheGetAsyncOnce()
    {
        // Arrange
        var key = "test_key";
        var serializedBytes = new byte[] { 1, 2, 3 };

        _cache
            .Setup(c => c.GetAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync(serializedBytes);

        _serializer
            .Setup(s => s.Deserialize<TestData>(serializedBytes))
            .Returns(CreateTestData());

        // Act
        await _storage.GetAsync<TestData>(key, removeOnRetrieval: false);

        // Assert
        _cache.Verify(c => c.GetAsync(key, It.IsAny<CancellationToken>()), Times.Once);
    }

    /// <summary>
    /// Verifies that GetAsync calls serializer.Deserialize when data exists.
    /// Deserialization is required to convert stored bytes back to objects.
    /// </summary>
    [Fact]
    public async Task GetAsync_WhenDataExists_ShouldCallDeserialize()
    {
        // Arrange
        var key = "test_key";
        var serializedBytes = new byte[] { 1, 2, 3 };

        _cache
            .Setup(c => c.GetAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync(serializedBytes);

        _serializer
            .Setup(s => s.Deserialize<TestData>(serializedBytes))
            .Returns(CreateTestData());

        // Act
        await _storage.GetAsync<TestData>(key, removeOnRetrieval: false);

        // Assert
        _serializer.Verify(s => s.Deserialize<TestData>(serializedBytes), Times.Once);
    }

    /// <summary>
    /// Verifies that GetAsync does not call deserialize when data is null.
    /// Deserialization is unnecessary when cache returns no data.
    /// </summary>
    [Fact]
    public async Task GetAsync_WhenDataIsNull_ShouldNotCallDeserialize()
    {
        // Arrange
        var key = "non_existent_key";

        _cache
            .Setup(c => c.GetAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);

        // Act
        await _storage.GetAsync<TestData>(key, removeOnRetrieval: false);

        // Assert - MockBehavior.Strict ensures no unexpected calls to Deserialize
    }

    /// <summary>
    /// Verifies that GetAsync removes from cache when removeOnRetrieval is true.
    /// One-time retrieval pattern is useful for tokens and codes that should be used once.
    /// </summary>
    [Fact]
    public async Task GetAsync_WithRemoveOnRetrievalTrue_ShouldRemoveFromCache()
    {
        // Arrange
        var key = "test_key";
        var serializedBytes = new byte[] { 1, 2, 3 };

        _cache
            .Setup(c => c.GetAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync(serializedBytes);

        _serializer
            .Setup(s => s.Deserialize<TestData>(serializedBytes))
            .Returns(CreateTestData());

        _cache
            .Setup(c => c.RemoveAsync(key, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        await _storage.GetAsync<TestData>(key, removeOnRetrieval: true);

        // Assert
        _cache.Verify(c => c.RemoveAsync(key, It.IsAny<CancellationToken>()), Times.Once);
    }

    /// <summary>
    /// Verifies that GetAsync does not remove when removeOnRetrieval is false.
    /// Normal retrieval should leave the cached entry intact for future access.
    /// </summary>
    [Fact]
    public async Task GetAsync_WithRemoveOnRetrievalFalse_ShouldNotRemoveFromCache()
    {
        // Arrange
        var key = "test_key";
        var serializedBytes = new byte[] { 1, 2, 3 };

        _cache
            .Setup(c => c.GetAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync(serializedBytes);

        _serializer
            .Setup(s => s.Deserialize<TestData>(serializedBytes))
            .Returns(CreateTestData());

        // Act
        await _storage.GetAsync<TestData>(key, removeOnRetrieval: false);

        // Assert - MockBehavior.Strict ensures RemoveAsync is not called
    }

    /// <summary>
    /// Verifies that GetAsync throws ArgumentNullException for null key.
    /// Keys are required to identify cache entries for retrieval.
    /// </summary>
    [Fact]
    public async Task GetAsync_WithNullKey_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await _storage.GetAsync<TestData>(null!, removeOnRetrieval: false));
    }

    /// <summary>
    /// Verifies that GetAsync uses CancellationToken.None when token is null.
    /// Default cancellation token ensures the operation can still be tracked.
    /// </summary>
    [Fact]
    public async Task GetAsync_WithNullToken_ShouldUseCancellationTokenNone()
    {
        // Arrange
        var key = "test_key";
        CancellationToken capturedToken = default;

        _cache
            .Setup(c => c.GetAsync(key, It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((_, token) => capturedToken = token)
            .ReturnsAsync((byte[]?)null);

        // Act
        await _storage.GetAsync<TestData>(key, removeOnRetrieval: false, token: null);

        // Assert
        Assert.Equal(CancellationToken.None, capturedToken);
    }

    /// <summary>
    /// Verifies that RemoveAsync calls cache.RemoveAsync with key.
    /// Removal operations should delegate to the underlying cache.
    /// </summary>
    [Fact]
    public async Task RemoveAsync_ShouldCallCacheRemoveAsync()
    {
        // Arrange
        var key = "test_key";

        _cache
            .Setup(c => c.RemoveAsync(key, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        await _storage.RemoveAsync(key);

        // Assert
        _cache.Verify(c => c.RemoveAsync(key, It.IsAny<CancellationToken>()), Times.Once);
    }

    /// <summary>
    /// Verifies that RemoveAsync uses CancellationToken.None when token is null.
    /// Default cancellation token ensures the operation can still be tracked.
    /// </summary>
    [Fact]
    public async Task RemoveAsync_WithNullToken_ShouldUseCancellationTokenNone()
    {
        // Arrange
        var key = "test_key";
        CancellationToken capturedToken = default;

        _cache
            .Setup(c => c.RemoveAsync(key, It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((_, token) => capturedToken = token)
            .Returns(Task.CompletedTask);

        // Act
        await _storage.RemoveAsync(key, token: null);

        // Assert
        Assert.Equal(CancellationToken.None, capturedToken);
    }

    /// <summary>
    /// Verifies that RemoveAsync passes provided cancellation token to cache.
    /// Cancellation tokens allow removal operations to be cancelled when needed.
    /// </summary>
    [Fact]
    public async Task RemoveAsync_WithProvidedToken_ShouldPassTokenToCache()
    {
        // Arrange
        var key = "test_key";
        var cancellationTokenSource = new CancellationTokenSource();
        var expectedToken = cancellationTokenSource.Token;
        CancellationToken capturedToken = default;

        _cache
            .Setup(c => c.RemoveAsync(key, It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((_, token) => capturedToken = token)
            .Returns(Task.CompletedTask);

        // Act
        await _storage.RemoveAsync(key, expectedToken);

        // Assert
        Assert.Equal(expectedToken, capturedToken);
    }

    /// <summary>
    /// Verifies integration: Set then Get returns same object.
    /// Complete write-read cycle should preserve object data.
    /// </summary>
    [Fact]
    public async Task Integration_SetThenGet_ShouldReturnSameObject()
    {
        // Arrange
        var key = "integration_key";
        var originalData = CreateTestData("integration_test", 123);
        var serializedBytes = new byte[] { 10, 20, 30 };
        var options = CreateStorageOptions(absoluteExpirationRelativeToNow: TimeSpan.FromMinutes(10));

        _serializer
            .Setup(s => s.Serialize(originalData))
            .Returns(serializedBytes);

        _cache
            .Setup(c => c.SetAsync(
                key,
                serializedBytes,
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _cache
            .Setup(c => c.GetAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync(serializedBytes);

        _serializer
            .Setup(s => s.Deserialize<TestData>(serializedBytes))
            .Returns(originalData);

        // Act
        await _storage.SetAsync(key, originalData, options);
        var retrievedData = await _storage.GetAsync<TestData>(key, removeOnRetrieval: false);

        // Assert
        Assert.Same(originalData, retrievedData);
    }

    /// <summary>
    /// Verifies integration: Set then Get with removeOnRetrieval removes object.
    /// After retrieval with removal, subsequent Get should return null.
    /// </summary>
    [Fact]
    public async Task Integration_SetThenGetWithRemoval_ShouldRemoveObject()
    {
        // Arrange
        var key = "removal_key";
        var data = CreateTestData();
        var serializedBytes = new byte[] { 1, 2, 3 };
        var options = CreateStorageOptions();

        _serializer
            .Setup(s => s.Serialize(data))
            .Returns(serializedBytes);

        _cache
            .Setup(c => c.SetAsync(
                key,
                serializedBytes,
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _cache
            .Setup(c => c.GetAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync(serializedBytes);

        _serializer
            .Setup(s => s.Deserialize<TestData>(serializedBytes))
            .Returns(data);

        _cache
            .Setup(c => c.RemoveAsync(key, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        await _storage.SetAsync(key, data, options);
        await _storage.GetAsync<TestData>(key, removeOnRetrieval: true);

        // Assert
        _cache.Verify(c => c.RemoveAsync(key, It.IsAny<CancellationToken>()), Times.Once);
    }

    /// <summary>
    /// Verifies that multiple different keys store independently.
    /// Storage should maintain separate entries for different keys without interference.
    /// </summary>
    [Fact]
    public async Task Integration_MultipleDifferentKeys_ShouldStoreIndependently()
    {
        // Arrange
        var key1 = "key_1";
        var key2 = "key_2";
        var data1 = CreateTestData("data_1", 100);
        var data2 = CreateTestData("data_2", 200);
        var bytes1 = new byte[] { 1, 1, 1 };
        var bytes2 = new byte[] { 2, 2, 2 };
        var options = CreateStorageOptions();

        _serializer
            .Setup(s => s.Serialize(data1))
            .Returns(bytes1);

        _serializer
            .Setup(s => s.Serialize(data2))
            .Returns(bytes2);

        _cache
            .Setup(c => c.SetAsync(
                key1,
                bytes1,
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _cache
            .Setup(c => c.SetAsync(
                key2,
                bytes2,
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _cache
            .Setup(c => c.GetAsync(key1, It.IsAny<CancellationToken>()))
            .ReturnsAsync(bytes1);

        _cache
            .Setup(c => c.GetAsync(key2, It.IsAny<CancellationToken>()))
            .ReturnsAsync(bytes2);

        _serializer
            .Setup(s => s.Deserialize<TestData>(bytes1))
            .Returns(data1);

        _serializer
            .Setup(s => s.Deserialize<TestData>(bytes2))
            .Returns(data2);

        // Act
        await _storage.SetAsync(key1, data1, options);
        await _storage.SetAsync(key2, data2, options);
        var result1 = await _storage.GetAsync<TestData>(key1, removeOnRetrieval: false);
        var result2 = await _storage.GetAsync<TestData>(key2, removeOnRetrieval: false);

        // Assert
        Assert.Same(data1, result1);
        Assert.Same(data2, result2);
    }

    /// <summary>
    /// Verifies that different StorageOptions combinations work correctly.
    /// Various expiration strategies should be properly translated to cache options.
    /// </summary>
    [Fact]
    public async Task Integration_DifferentStorageOptions_ShouldWorkCorrectly()
    {
        // Arrange
        var key1 = "absolute_key";
        var key2 = "relative_key";
        var key3 = "sliding_key";
        var data = CreateTestData();
        var bytes = new byte[] { 1, 2, 3 };

        var absoluteOptions = CreateStorageOptions(
            absoluteExpiration: DateTimeOffset.UtcNow.AddHours(2));

        var relativeOptions = CreateStorageOptions(
            absoluteExpirationRelativeToNow: TimeSpan.FromMinutes(15));

        var slidingOptions = CreateStorageOptions(
            slidingExpiration: TimeSpan.FromMinutes(5));

        _serializer
            .Setup(s => s.Serialize(data))
            .Returns(bytes);

        _cache
            .Setup(c => c.SetAsync(
                key1,
                bytes,
                It.Is<DistributedCacheEntryOptions>(o => o.AbsoluteExpiration != null),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _cache
            .Setup(c => c.SetAsync(
                key2,
                bytes,
                It.Is<DistributedCacheEntryOptions>(o => o.AbsoluteExpirationRelativeToNow != null),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _cache
            .Setup(c => c.SetAsync(
                key3,
                bytes,
                It.Is<DistributedCacheEntryOptions>(o => o.SlidingExpiration != null),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        await _storage.SetAsync(key1, data, absoluteOptions);
        await _storage.SetAsync(key2, data, relativeOptions);
        await _storage.SetAsync(key3, data, slidingOptions);

        // Assert
        _cache.Verify(c => c.SetAsync(
            key1,
            bytes,
            It.Is<DistributedCacheEntryOptions>(o => o.AbsoluteExpiration != null),
            It.IsAny<CancellationToken>()),
            Times.Once);

        _cache.Verify(c => c.SetAsync(
            key2,
            bytes,
            It.Is<DistributedCacheEntryOptions>(o => o.AbsoluteExpirationRelativeToNow != null),
            It.IsAny<CancellationToken>()),
            Times.Once);

        _cache.Verify(c => c.SetAsync(
            key3,
            bytes,
            It.Is<DistributedCacheEntryOptions>(o => o.SlidingExpiration != null),
            It.IsAny<CancellationToken>()),
            Times.Once);
    }
}
