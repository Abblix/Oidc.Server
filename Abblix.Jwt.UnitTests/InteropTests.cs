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

using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Cross-validation tests between Abblix JWT implementation and Microsoft's IdentityModel library (JsonWebTokenHandler).
/// Tests ensure compatibility by:
/// 1. Creating JWT with Microsoft → Validating with Abblix
/// 2. Creating JWT with Abblix → Validating with Microsoft
///
/// These tests prove that Abblix's custom JWT implementation is fully compatible with industry-standard
/// JWT libraries. Microsoft's library successfully validates tokens created by Abblix, including signature
/// verification, which confirms our signing implementation is correct per RFC 7515 (JWS).
///
/// Note: The 'iat' (Issued At) claim is OPTIONAL per RFC 7519 Section 4.1.6. Tokens without 'iat' are valid.
/// </summary>
/// <remarks>
/// MapInboundClaims is disabled on Microsoft's handler to preserve original JWT claim names (sub, iss, aud, etc.)
/// instead of mapping them to .NET claim types (http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier).
/// This ensures tests verify actual JWT claim values as they appear in the token.
/// </remarks>
public class InteropTests
{
	private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

	private static IServiceProvider CreateServiceProvider()
	{
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		services.AddJsonWebTokens();
		return services.BuildServiceProvider();
	}

	private readonly JsonWebTokenHandler _microsoftHandler = new()
	{
		MapInboundClaims = false
	};

	#region Unsigned JWT Tests

	[Fact]
	public async Task Create_AbblixUnsignedJwt_MicrosoftValidates_Success()
	{
		// Arrange - Create unsigned JWT with Abblix
		var abblixToken = new JsonWebToken
		{
			Header = { Type = "JWT" },
			Payload =
			{
				Subject = "1234567890",
				Issuer = "https://issuer.example.com",
				Audiences = ["https://audience.example.com"],
				IssuedAt = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
				ExpiresAt = new DateTime(2024, 12, 31, 23, 59, 59, DateTimeKind.Utc),
			},
		};

		abblixToken.Payload.Json["name"] = "John Doe";
		abblixToken.Payload.Json["email"] = "john@example.com";

		// Abblix creates the token
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwt = await creator.IssueAsync(abblixToken, signingKey: null);

		// Act - Validate with Microsoft library
		var microsoftToken = _microsoftHandler.ReadJsonWebToken(jwt);

		// Assert - Verify Microsoft can read it
		Assert.Equal("none", microsoftToken.Alg);
		Assert.Equal("JWT", microsoftToken.Typ);
		Assert.Equal("1234567890", microsoftToken.Subject);
		Assert.Equal("https://issuer.example.com", microsoftToken.Issuer);
		Assert.Contains("https://audience.example.com", microsoftToken.Audiences);
		Assert.Equal("John Doe", microsoftToken.Claims.First(c => c.Type == "name").Value);
		Assert.Equal("john@example.com", microsoftToken.Claims.First(c => c.Type == "email").Value);
	}

	[Fact]
	public async Task Create_MicrosoftUnsignedJwt_AbblixValidates_Success()
	{
		// Arrange - Create unsigned JWT with Microsoft library
		var descriptor = new SecurityTokenDescriptor
		{
			Subject = new System.Security.Claims.ClaimsIdentity([
				new System.Security.Claims.Claim("sub", "1234567890"),
				new System.Security.Claims.Claim("name", "John Doe"),
				new System.Security.Claims.Claim("email", "john@example.com")
			]),
			Issuer = "https://issuer.example.com",
			Audience = "https://audience.example.com",
			NotBefore = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
			Expires = new DateTime(2024, 12, 31, 23, 59, 59, DateTimeKind.Utc),
			SigningCredentials = null  // Unsigned token
		};

		var jwt = _microsoftHandler.CreateToken(descriptor);

		// Act - Validate with Abblix
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var result = await validator.ValidateAsync(jwt, new ValidationParameters
		{
			ValidateIssuer = _ => Task.FromResult(true),
			ValidateAudience = _ => Task.FromResult(true),
			Options = ValidationOptions.ValidateIssuer | ValidationOptions.ValidateAudience
		});

		// Assert
		Assert.True(result.TryGetSuccess(out var token));
		Assert.Equal("1234567890", token.Payload.Subject);
		Assert.Equal("https://issuer.example.com", token.Payload.Issuer);
		Assert.Contains("https://audience.example.com", token.Payload.Audiences);
		Assert.Equal("John Doe", token.Payload.Json["name"]?.GetValue<string>());
		Assert.Equal("john@example.com", token.Payload.Json["email"]?.GetValue<string>());
	}

	[Fact]
	public async Task Create_MicrosoftUnsignedJwt_ComplexClaims_AbblixValidates_Success()
	{
		// Arrange - Create JWT with complex claim types
		var descriptor = new SecurityTokenDescriptor
		{
			Subject = new System.Security.Claims.ClaimsIdentity([
				new System.Security.Claims.Claim("sub", "user123"),
				new System.Security.Claims.Claim("roles", "admin"),
				new System.Security.Claims.Claim("roles", "user"),  // Multiple values
				new System.Security.Claims.Claim("age", "30"),
				new System.Security.Claims.Claim("verified", "true")
			]),
			Issuer = "https://issuer.example.com",
			SigningCredentials = null
		};

		var jwt = _microsoftHandler.CreateToken(descriptor);

		// Act - Validate with Abblix
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var result = await validator.ValidateAsync(jwt, new ValidationParameters
		{
			ValidateIssuer = _ => Task.FromResult(true),
			Options = ValidationOptions.ValidateIssuer
		});

		// Assert
		Assert.True(result.TryGetSuccess(out var token));
		Assert.Equal("user123", token.Payload.Subject);

		// Microsoft serializes multiple claim values as JSON array
		var roles = token.Payload.Json["roles"];
		Assert.NotNull(roles);
		if (roles is System.Text.Json.Nodes.JsonArray rolesArray)
		{
			Assert.Equal(2, rolesArray.Count);
			Assert.Contains("admin", rolesArray.Select(r => r?.GetValue<string>()));
			Assert.Contains("user", rolesArray.Select(r => r?.GetValue<string>()));
		}
	}

	[Fact]
	public async Task Create_AbblixJwtWithMultipleAudiences_MicrosoftReads_Success()
	{
		// Arrange
		var abblixToken = new JsonWebToken
		{
			Payload =
			{
				Subject = "test-user",
				Issuer = "https://abblix.com",
				Audiences = ["aud1", "aud2", "aud3"],
				ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
			},
		};

		// Abblix creates unsigned token with multiple audiences
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwt = await creator.IssueAsync(abblixToken, signingKey: null);

		// Act - Read with Microsoft library
		var microsoftToken = _microsoftHandler.ReadJsonWebToken(jwt);

		// Assert - All audiences present
		var audiences = microsoftToken.Audiences.ToList();
		Assert.Equal(3, audiences.Count);
		Assert.Contains("aud1", audiences);
		Assert.Contains("aud2", audiences);
		Assert.Contains("aud3", audiences);
	}

	#endregion

	#region RSA Signing Tests

	public static TheoryData<string, string> RsaSigningAlgorithms => new()
	{
		{ SigningAlgorithms.RS256, SecurityAlgorithms.RsaSha256 },
		{ SigningAlgorithms.RS384, SecurityAlgorithms.RsaSha384 },
		{ SigningAlgorithms.RS512, SecurityAlgorithms.RsaSha512 },
		{ SigningAlgorithms.PS256, SecurityAlgorithms.RsaSsaPssSha256 },
		{ SigningAlgorithms.PS384, SecurityAlgorithms.RsaSsaPssSha384 },
		{ SigningAlgorithms.PS512, SecurityAlgorithms.RsaSsaPssSha512 },
	};

	[Theory]
	[MemberData(nameof(RsaSigningAlgorithms))]
	public async Task Create_AbblixSignedJwt_RsaAlgorithms_MicrosoftValidates_Success(
		string abblixAlgorithm,
		string microsoftAlgorithm)
	{
		// Arrange - Create RSA key with specific algorithm
		var rsaKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, abblixAlgorithm);

		var abblixToken = new JsonWebToken
		{
			Header = { Type = "JWT" },
			Payload =
			{
				Subject = "test-user",
				Issuer = "https://abblix.com",
				Audiences = ["test-audience"],
				ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
			},
		};

		// Abblix creates and signs the token
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwt = await creator.IssueAsync(abblixToken, rsaKey);

		// Act - Validate with Microsoft library
		var microsoftKey = rsaKey.ToSecurityKey();
		var validationParameters = new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = microsoftKey,
			ValidateIssuer = true,
			ValidIssuer = "https://abblix.com",
			ValidateAudience = true,
			ValidAudience = "test-audience",
			ValidateLifetime = true,
			ClockSkew = TimeSpan.FromMinutes(5),
		};

		var result = await _microsoftHandler.ValidateTokenAsync(jwt, validationParameters);

		// Assert - Microsoft successfully validated Abblix's signature
		Assert.True(result.IsValid, $"Validation failed for {abblixAlgorithm}: {result.Exception?.Message}");
		Assert.NotNull(result.ClaimsIdentity);
		Assert.Equal("test-user", result.ClaimsIdentity.FindFirst("sub")?.Value);

		// Verify the algorithm used matches expectations
		var microsoftToken = Assert.IsType<Microsoft.IdentityModel.JsonWebTokens.JsonWebToken>(result.SecurityToken);
		Assert.Equal(microsoftAlgorithm, microsoftToken.Alg);
	}

	[Theory]
	[MemberData(nameof(RsaSigningAlgorithms))]
	public async Task Create_MicrosoftSignedJwt_RsaAlgorithms_AbblixValidates_Success(
		string abblixAlgorithm,
		string microsoftAlgorithm)
	{
		// Arrange - Create RSA key
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, abblixAlgorithm);

		var descriptor = new SecurityTokenDescriptor
		{
			Subject = new System.Security.Claims.ClaimsIdentity([
				new System.Security.Claims.Claim("sub", "microsoft-user")
			]),
			Issuer = "https://microsoft.com",
			Audience = "abblix-app",
			Expires = DateTime.UtcNow.AddHours(1),
			SigningCredentials = new SigningCredentials(
				signingKey.ToSecurityKey(),
				microsoftAlgorithm),
		};

		var jwt = _microsoftHandler.CreateToken(descriptor);

		// Act - Validate with Abblix
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var result = await validator.ValidateAsync(jwt, new ValidationParameters
		{
			Options = ValidationOptions.ValidateIssuer |
					  ValidationOptions.RequireSignedTokens |
					  ValidationOptions.ValidateIssuerSigningKey,
			ValidateIssuer = iss => Task.FromResult(iss == "https://microsoft.com"),
			ResolveIssuerSigningKeys = _ => new[] { signingKey }.ToAsyncEnumerable(),
		});

		// Assert
		Assert.True(result.TryGetSuccess(out var token),
			result.TryGetFailure(out var error) ? $"Validation failed for {abblixAlgorithm}: {error.Error} - {error.ErrorDescription}" : "Validation failed");
		Assert.Equal("microsoft-user", token.Payload.Subject);
	}

	#endregion

	#region EC Signing Tests

	public static TheoryData<string, string, string> EcSigningAlgorithms => new()
	{
		{ SigningAlgorithms.ES256, SecurityAlgorithms.EcdsaSha256, EllipticCurveTypes.P256 },
		{ SigningAlgorithms.ES384, SecurityAlgorithms.EcdsaSha384, EllipticCurveTypes.P384 },
		{ SigningAlgorithms.ES512, SecurityAlgorithms.EcdsaSha512, EllipticCurveTypes.P521 },
	};

	[Theory]
	[MemberData(nameof(EcSigningAlgorithms))]
	public async Task Create_AbblixSignedJwt_EcAlgorithms_MicrosoftValidates_Success(
		string abblixAlgorithm,
		string microsoftAlgorithm,
		string curve)
	{
		// Arrange - Create EC key with specific curve and algorithm
		var ecKey = JsonWebKeyFactory.CreateEllipticCurve(curve, abblixAlgorithm);

		var abblixToken = new JsonWebToken
		{
			Header = { Type = "JWT" },
			Payload =
			{
				Subject = "ec-test-user",
				Issuer = "https://abblix.com",
				Audiences = ["test-audience"],
				ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
			},
		};

		// Abblix creates and signs the token
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwt = await creator.IssueAsync(abblixToken, ecKey);

		// Act - Validate with Microsoft library
		var microsoftKey = ecKey.ToSecurityKey();
		var validationParameters = new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = microsoftKey,
			ValidateIssuer = true,
			ValidIssuer = "https://abblix.com",
			ValidateAudience = true,
			ValidAudience = "test-audience",
			ValidateLifetime = true,
			ClockSkew = TimeSpan.FromMinutes(5),
		};

		var result = await _microsoftHandler.ValidateTokenAsync(jwt, validationParameters);

		// Assert - Microsoft successfully validated Abblix's ECDSA signature
		Assert.True(result.IsValid, $"Validation failed for {abblixAlgorithm}: {result.Exception?.Message}");
		Assert.NotNull(result.ClaimsIdentity);
		Assert.Equal("ec-test-user", result.ClaimsIdentity.FindFirst("sub")?.Value);

		// Verify the algorithm used matches expectations
		var microsoftToken = Assert.IsType<Microsoft.IdentityModel.JsonWebTokens.JsonWebToken>(result.SecurityToken);
		Assert.Equal(microsoftAlgorithm, microsoftToken.Alg);
	}

	[Theory]
	[MemberData(nameof(EcSigningAlgorithms))]
	public async Task Create_MicrosoftSignedJwt_EcAlgorithms_AbblixValidates_Success(
		string abblixAlgorithm,
		string microsoftAlgorithm,
		string curve)
	{
		// Arrange - Create EC key
		var signingKey = JsonWebKeyFactory.CreateEllipticCurve(curve, abblixAlgorithm);

		var descriptor = new SecurityTokenDescriptor
		{
			Subject = new System.Security.Claims.ClaimsIdentity([
				new System.Security.Claims.Claim("sub", "microsoft-ec-user")
			]),
			Issuer = "https://microsoft.com",
			Audience = "abblix-app",
			Expires = DateTime.UtcNow.AddHours(1),
			SigningCredentials = new SigningCredentials(
				signingKey.ToSecurityKey(),
				microsoftAlgorithm),
		};

		var jwt = _microsoftHandler.CreateToken(descriptor);

		// Act - Validate with Abblix
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var result = await validator.ValidateAsync(jwt, new ValidationParameters
		{
			Options = ValidationOptions.ValidateIssuer |
					  ValidationOptions.RequireSignedTokens |
					  ValidationOptions.ValidateIssuerSigningKey,
			ValidateIssuer = iss => Task.FromResult(iss == "https://microsoft.com"),
			ResolveIssuerSigningKeys = _ => new[] { signingKey }.ToAsyncEnumerable(),
		});

		// Assert
		Assert.True(result.TryGetSuccess(out var token),
			result.TryGetFailure(out var error) ? $"Validation failed for {abblixAlgorithm}: {error.Error} - {error.ErrorDescription}" : "Validation failed");
		Assert.Equal("microsoft-ec-user", token.Payload.Subject);
	}

	#endregion

	#region HMAC Signing Tests

	public static TheoryData<string, string> HmacSigningAlgorithms => new()
	{
		{ SigningAlgorithms.HS256, SecurityAlgorithms.HmacSha256 },
		{ SigningAlgorithms.HS384, SecurityAlgorithms.HmacSha384 },
		{ SigningAlgorithms.HS512, SecurityAlgorithms.HmacSha512 },
	};

	[Theory]
	[MemberData(nameof(HmacSigningAlgorithms))]
	public async Task Create_AbblixSignedJwt_HmacAlgorithms_MicrosoftValidates_Success(
		string abblixAlgorithm,
		string microsoftAlgorithm)
	{
		// Arrange - Create HMAC key
		var hmacKey = JsonWebKeyFactory.CreateHmac(abblixAlgorithm);

		var abblixToken = new JsonWebToken
		{
			Header = { Type = "JWT" },
			Payload =
			{
				Subject = "hmac-test-user",
				Issuer = "https://abblix.com",
				Audiences = ["test-audience"],
				ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
			},
		};

		// Abblix creates and signs the token
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwt = await creator.IssueAsync(abblixToken, hmacKey);

		// Act - Validate with Microsoft library
		var microsoftKey = hmacKey.ToSecurityKey();
		var validationParameters = new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = microsoftKey,
			ValidateIssuer = true,
			ValidIssuer = "https://abblix.com",
			ValidateAudience = true,
			ValidAudience = "test-audience",
			ValidateLifetime = true,
			ClockSkew = TimeSpan.FromMinutes(5),
		};

		var result = await _microsoftHandler.ValidateTokenAsync(jwt, validationParameters);

		// Assert - Microsoft successfully validated Abblix's HMAC signature
		Assert.True(result.IsValid, $"Validation failed for {abblixAlgorithm}: {result.Exception?.Message}");
		Assert.NotNull(result.ClaimsIdentity);
		Assert.Equal("hmac-test-user", result.ClaimsIdentity.FindFirst("sub")?.Value);

		// Verify the algorithm used matches expectations
		var microsoftToken = Assert.IsType<Microsoft.IdentityModel.JsonWebTokens.JsonWebToken>(result.SecurityToken);
		Assert.Equal(microsoftAlgorithm, microsoftToken.Alg);
	}

	[Theory]
	[MemberData(nameof(HmacSigningAlgorithms))]
	public async Task Create_MicrosoftSignedJwt_HmacAlgorithms_AbblixValidates_Success(
		string abblixAlgorithm,
		string microsoftAlgorithm)
	{
		// Arrange - Create HMAC key
		var signingKey = JsonWebKeyFactory.CreateHmac(abblixAlgorithm);

		var descriptor = new SecurityTokenDescriptor
		{
			Subject = new System.Security.Claims.ClaimsIdentity([
				new System.Security.Claims.Claim("sub", "microsoft-hmac-user")
			]),
			Issuer = "https://microsoft.com",
			Audience = "abblix-app",
			Expires = DateTime.UtcNow.AddHours(1),
			SigningCredentials = new SigningCredentials(
				signingKey.ToSecurityKey(),
				microsoftAlgorithm),
		};

		var jwt = _microsoftHandler.CreateToken(descriptor);

		// Act - Validate with Abblix
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var result = await validator.ValidateAsync(jwt, new ValidationParameters
		{
			Options = ValidationOptions.ValidateIssuer |
					  ValidationOptions.RequireSignedTokens |
					  ValidationOptions.ValidateIssuerSigningKey,
			ValidateIssuer = iss => Task.FromResult(iss == "https://microsoft.com"),
			ResolveIssuerSigningKeys = _ => new[] { signingKey }.ToAsyncEnumerable(),
		});

		// Assert
		Assert.True(result.TryGetSuccess(out var token),
			result.TryGetFailure(out var error) ? $"Validation failed for {abblixAlgorithm}: {error.Error} - {error.ErrorDescription}" : "Validation failed");
		Assert.Equal("microsoft-hmac-user", token.Payload.Subject);
	}

	#endregion

	#region JWE Encryption Tests

	public static TheoryData<string, string, string, string> JweEncryptionAlgorithms => new()
	{
		// RSA-OAEP with all AES-CBC-HMAC variants (Microsoft supports)
		{ EncryptionAlgorithms.KeyManagement.RsaOaep, SecurityAlgorithms.RsaOAEP,
		  EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256, SecurityAlgorithms.Aes128CbcHmacSha256 },
		{ EncryptionAlgorithms.KeyManagement.RsaOaep, SecurityAlgorithms.RsaOAEP,
		  EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384, SecurityAlgorithms.Aes192CbcHmacSha384 },
		{ EncryptionAlgorithms.KeyManagement.RsaOaep, SecurityAlgorithms.RsaOAEP,
		  EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512, SecurityAlgorithms.Aes256CbcHmacSha512 },

		// RSA1_5 with all AES-CBC-HMAC variants (Microsoft supports, but deprecated)
		{ EncryptionAlgorithms.KeyManagement.Rsa1_5, SecurityAlgorithms.RsaPKCS1,
		  EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256, SecurityAlgorithms.Aes128CbcHmacSha256 },
		{ EncryptionAlgorithms.KeyManagement.Rsa1_5, SecurityAlgorithms.RsaPKCS1,
		  EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384, SecurityAlgorithms.Aes192CbcHmacSha384 },
		{ EncryptionAlgorithms.KeyManagement.Rsa1_5, SecurityAlgorithms.RsaPKCS1,
		  EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512, SecurityAlgorithms.Aes256CbcHmacSha512 },

		// Note: RSA-OAEP-256 omitted from interop tests because Microsoft's IdentityModel library
		// doesn't have a proper constant for it (SecurityAlgorithms.RsaOaepKeyWrap is actually RSA-OAEP with SHA-1)
	};

	public static TheoryData<string, string> AbblixOnlyEncryptionAlgorithms => new()
	{
		// RSA-OAEP-256 with all AES-CBC-HMAC variants (Abblix supports, Microsoft doesn't have proper constant)
		{ EncryptionAlgorithms.KeyManagement.RsaOaep256, EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256 },
		{ EncryptionAlgorithms.KeyManagement.RsaOaep256, EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384 },
		{ EncryptionAlgorithms.KeyManagement.RsaOaep256, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512 },

		// RSA-OAEP with AES-GCM content encryption (Abblix supports, Microsoft doesn't support GCM with RSA key wrap)
		{ EncryptionAlgorithms.KeyManagement.RsaOaep, EncryptionAlgorithms.ContentEncryption.Aes128Gcm },
		{ EncryptionAlgorithms.KeyManagement.RsaOaep, EncryptionAlgorithms.ContentEncryption.Aes192Gcm },
		{ EncryptionAlgorithms.KeyManagement.RsaOaep, EncryptionAlgorithms.ContentEncryption.Aes256Gcm },

		// RSA-OAEP-256 with AES-GCM content encryption (Abblix supports, Microsoft doesn't support)
		{ EncryptionAlgorithms.KeyManagement.RsaOaep256, EncryptionAlgorithms.ContentEncryption.Aes128Gcm },
		{ EncryptionAlgorithms.KeyManagement.RsaOaep256, EncryptionAlgorithms.ContentEncryption.Aes192Gcm },
		{ EncryptionAlgorithms.KeyManagement.RsaOaep256, EncryptionAlgorithms.ContentEncryption.Aes256Gcm },

		// RSA1_5 with AES-GCM content encryption (Abblix supports, Microsoft doesn't support GCM with RSA key wrap)
		{ EncryptionAlgorithms.KeyManagement.Rsa1_5, EncryptionAlgorithms.ContentEncryption.Aes128Gcm },
		{ EncryptionAlgorithms.KeyManagement.Rsa1_5, EncryptionAlgorithms.ContentEncryption.Aes192Gcm },
		{ EncryptionAlgorithms.KeyManagement.Rsa1_5, EncryptionAlgorithms.ContentEncryption.Aes256Gcm },
	};

	[Theory]
	[MemberData(nameof(JweEncryptionAlgorithms))]
	public async Task Create_AbblixEncryptedJwt_AllAlgorithms_MicrosoftDecrypts_Success(
		string abblixKeyEncAlg,
		string microsoftKeyEncAlg,
		string abblixContentEncAlg,
		string microsoftContentEncAlg)
	{
		// Arrange - Create signing and encryption keys
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
		var encryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption, abblixKeyEncAlg);

		var abblixToken = new JsonWebToken
		{
			Header = { Type = "JWT" },
			Payload =
			{
				Subject = "test-user",
				Issuer = "https://abblix.com",
				Audiences = ["test-audience"],
				ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
			},
		};

		abblixToken.Payload.Json["name"] = "John Doe";
		abblixToken.Payload.Json["role"] = "admin";

		// Abblix creates signed and encrypted JWT
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwt = await creator.IssueAsync(
			abblixToken,
			signingKey,
			encryptionKey,
			keyEncryptionAlgorithm: abblixKeyEncAlg,
			contentEncryptionAlgorithm: abblixContentEncAlg);

		// Act - Microsoft decrypts and validates
		var microsoftEncKey = new EncryptingCredentials(
			encryptionKey.ToSecurityKey(),
			microsoftKeyEncAlg,
			microsoftContentEncAlg);

		var microsoftSignKey = signingKey.ToSecurityKey();

		var validationParameters = new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = microsoftSignKey,
			ValidateIssuer = true,
			ValidIssuer = "https://abblix.com",
			ValidateAudience = true,
			ValidAudience = "test-audience",
			ValidateLifetime = true,
			TokenDecryptionKey = microsoftEncKey.Key,
		};

		var result = await _microsoftHandler.ValidateTokenAsync(jwt, validationParameters);

		// Assert - Microsoft successfully decrypted and validated
		Assert.True(result.IsValid,
			$"Validation failed for {abblixKeyEncAlg}/{abblixContentEncAlg}: {result.Exception?.Message}");
		Assert.NotNull(result.ClaimsIdentity);
		Assert.Equal("test-user", result.ClaimsIdentity.FindFirst("sub")?.Value);
		Assert.Equal("John Doe", result.ClaimsIdentity.FindFirst("name")?.Value);
		Assert.Equal("admin", result.ClaimsIdentity.FindFirst("role")?.Value);
	}

	[Theory]
	[MemberData(nameof(JweEncryptionAlgorithms))]
	public async Task Create_MicrosoftEncryptedJwt_AllAlgorithms_AbblixDecrypts_Success(
		string abblixKeyEncAlg,
		string microsoftKeyEncAlg,
		string abblixContentEncAlg,
		string microsoftContentEncAlg)
	{
		// Arrange - Create keys
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
		var encryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption, abblixKeyEncAlg);

		// Microsoft creates signed and encrypted JWT
		var claims = new[]
		{
			new System.Security.Claims.Claim("sub", "microsoft-user"),
			new System.Security.Claims.Claim("name", "Jane Smith"),
			new System.Security.Claims.Claim("email", "jane@example.com"),
		};

		var descriptor = new SecurityTokenDescriptor
		{
			Subject = new System.Security.Claims.ClaimsIdentity(claims),
			Issuer = "https://microsoft.example.com",
			Audience = "abblix-app",
			Expires = DateTime.UtcNow.AddHours(1),
			SigningCredentials = new SigningCredentials(
				signingKey.ToSecurityKey(),
				SecurityAlgorithms.RsaSha256),
			EncryptingCredentials = new EncryptingCredentials(
				encryptionKey.ToSecurityKey(),
				microsoftKeyEncAlg,
				microsoftContentEncAlg),
		};

		var jwt = _microsoftHandler.CreateToken(descriptor);

		// Act - Abblix decrypts and validates
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var validationResult = await validator.ValidateAsync(
			jwt,
			new ValidationParameters
			{
				Options = ValidationOptions.ValidateIssuer |
						  ValidationOptions.ValidateAudience |
						  ValidationOptions.RequireSignedTokens |
						  ValidationOptions.ValidateIssuerSigningKey,

				ValidateIssuer = iss => Task.FromResult(iss == "https://microsoft.example.com"),
				ValidateAudience = aud => Task.FromResult(aud.Contains("abblix-app")),
				ResolveIssuerSigningKeys = _ => new[] { signingKey }.ToAsyncEnumerable(),
				ResolveTokenDecryptionKeys = _ => new[] { encryptionKey }.ToAsyncEnumerable(),
			});

		// Assert - Abblix successfully decrypted and validated Microsoft's JWE
		Assert.True(validationResult.TryGetSuccess(out var token),
			validationResult.TryGetFailure(out var error)
				? $"Validation failed for {abblixKeyEncAlg}/{abblixContentEncAlg}: {error.Error} - {error.ErrorDescription}"
				: "Validation failed");
		Assert.Equal("microsoft-user", token.Payload.Subject);
		Assert.Equal("Jane Smith", token.Payload.Json["name"]?.GetValue<string>());
		Assert.Equal("jane@example.com", token.Payload.Json["email"]?.GetValue<string>());
	}

	[Theory]
	[MemberData(nameof(AbblixOnlyEncryptionAlgorithms))]
	public async Task Create_AbblixEncryptedJwt_RsaOaep256AndAesGcm_AbblixDecrypts_Success(
		string keyEncAlg,
		string contentEncAlg)
	{
		// Arrange - Create signing and encryption keys
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
		var encryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption, keyEncAlg);

		var abblixToken = new JsonWebToken
		{
			Header = { Type = "JWT" },
			Payload =
			{
				Subject = "test-user",
				Issuer = "https://abblix.com",
				Audiences = ["test-audience"],
				ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
			},
		};

		abblixToken.Payload.Json["name"] = "John Doe";
		abblixToken.Payload.Json["role"] = "admin";

		// Abblix creates signed and encrypted JWT
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwt = await creator.IssueAsync(
			abblixToken,
			signingKey,
			encryptionKey,
			keyEncryptionAlgorithm: keyEncAlg,
			contentEncryptionAlgorithm: contentEncAlg);

		// Act - Abblix decrypts and validates
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var result = await validator.ValidateAsync(jwt, new ValidationParameters
		{
			Options = ValidationOptions.ValidateIssuer |
					  ValidationOptions.ValidateAudience |
					  ValidationOptions.RequireSignedTokens |
					  ValidationOptions.ValidateIssuerSigningKey,
			ValidateIssuer = iss => Task.FromResult(iss == "https://abblix.com"),
			ValidateAudience = aud => Task.FromResult(aud.Contains("test-audience")),
			ResolveIssuerSigningKeys = _ => new[] { signingKey }.ToAsyncEnumerable(),
			ResolveTokenDecryptionKeys = _ => new[] { encryptionKey }.ToAsyncEnumerable(),
		});

		// Assert - Abblix successfully decrypted and validated
		Assert.True(result.TryGetSuccess(out var token),
			result.TryGetFailure(out var error)
				? $"Validation failed for {keyEncAlg}/{contentEncAlg}: {error.Error} - {error.ErrorDescription}"
				: "Validation failed");
		Assert.Equal("test-user", token.Payload.Subject);
		Assert.Equal("John Doe", token.Payload.Json["name"]?.GetValue<string>());
		Assert.Equal("admin", token.Payload.Json["role"]?.GetValue<string>());
	}

	#endregion
}
