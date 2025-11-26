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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Abblix.Utils;
using Microsoft.IdentityModel.Tokens;

namespace Abblix.Jwt;

/// <summary>
/// Provides extension methods for the JsonWebKey model to simplify the process of populating its properties from different sources.
/// These methods enable easy conversion between JsonWebKey and various cryptographic representations.
/// </summary>
public static class JsonWebKeyExtensions
{
	/// <summary>
	/// Converts a JsonWebKey to SigningCredentials used in cryptographic operations, specifically for signing tokens.
	/// </summary>
	/// <param name="jsonWebKey">The JsonWebKey to convert.</param>
	/// <returns>SigningCredentials based on the provided JsonWebKey.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the algorithm is not supported.</exception>
	public static SigningCredentials ToSigningCredentials(this JsonWebKey jsonWebKey)
		=> new(jsonWebKey.ToSecurityKey(), jsonWebKey.Algorithm);

	/// <summary>
	/// Converts a JsonWebKey to a SecurityKey used in cryptographic operations.
	/// Supports RSA, Elliptic Curve, and symmetric (oct) keys.
	/// </summary>
	/// <param name="jsonWebKey">The JsonWebKey to convert.</param>
	/// <returns>SecurityKey based on the provided JsonWebKey.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the key type is not supported.</exception>
	public static SecurityKey ToSecurityKey(this JsonWebKey jsonWebKey)
	{
		return jsonWebKey switch
		{
			RsaJsonWebKey rsaKey
				=> new RsaSecurityKey(rsaKey.ToRsa()) { KeyId = rsaKey.KeyId },

			OctetJsonWebKey { KeyId: var keyId, KeyValue: {} keyValue }
				=> new SymmetricSecurityKey(keyValue) { KeyId = keyId },

			_ => throw new InvalidOperationException($"Unsupported key type: {jsonWebKey.KeyType}"),
		};
	}

	/// <summary>
	/// Converts a JsonWebKey to EncryptingCredentials used in cryptographic operations, specifically for encrypting tokens.
	/// </summary>
	/// <param name="jsonWebKey">The JsonWebKey to convert.</param>
	/// <returns>EncryptingCredentials based on the provided JsonWebKey.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the algorithm is not supported.</exception>
	public static EncryptingCredentials ToEncryptingCredentials(this JsonWebKey jsonWebKey)
	{
		return jsonWebKey.Algorithm switch
		{
			SecurityAlgorithms.RsaSha256 => new EncryptingCredentials(
				jsonWebKey.ToSecurityKey(),
				SecurityAlgorithms.RsaOAEP,
				SecurityAlgorithms.Aes128CbcHmacSha256),

			_ => throw new InvalidOperationException($"Not supported algorithm: {jsonWebKey.Algorithm}"),
		};
	}

	/// <summary>
	/// Converts an X509Certificate2 to a JsonWebKey. The private keys can be optionally included in the conversion.
	/// </summary>
	/// <param name="certificate">The X509Certificate2 to convert.</param>
	/// <param name="includePrivateKeys">Indicates whether to include private keys in the conversion.</param>
	/// <returns>A JsonWebKey representing the certificate.</returns>
	public static JsonWebKey ToJsonWebKey(this X509Certificate2 certificate, bool includePrivateKeys = false)
	{
		// Try ECDSA first
		var ecdsaPublicKey = certificate.GetECDsaPublicKey();
		if (ecdsaPublicKey != null)
		{
			var ecdsaPrivateKey = includePrivateKeys ? certificate.GetECDsaPrivateKey() : null;

			var jwk = CreateEcKey(new X509SecurityKey(certificate), SecurityAlgorithms.EcdsaSha256)
				.Apply(ecdsaPublicKey.ExportParameters(false))
				.Apply(certificate);

			if (ecdsaPrivateKey != null)
			{
				jwk = jwk.Apply(ecdsaPrivateKey.ExportParameters(true));
			}

			return jwk;
		}

		// Fall back to RSA
		var rsaPublicKey = certificate.GetRSAPublicKey();
		if (rsaPublicKey != null)
		{
			var rsaPrivateKey = includePrivateKeys ? certificate.GetRSAPrivateKey() : null;

			var jwk = CreateRsaKey(new X509SecurityKey(certificate), SecurityAlgorithms.RsaSha256)
				.Apply(rsaPublicKey.ExportParameters(false))
				.Apply(certificate);

			if (rsaPrivateKey != null)
			{
				jwk = jwk.Apply(rsaPrivateKey.ExportParameters(true));
			}

			return jwk;
		}

		throw new InvalidOperationException($"Certificate does not contain a supported public key algorithm");
	}

	/// <summary>
	/// Converts a SecurityKey to a JsonWebKey with a specified algorithm. The private keys can be optionally included.
	/// </summary>
	/// <param name="key">The SecurityKey to convert.</param>
	/// <param name="algorithm">The algorithm to be used with the key.</param>
	/// <param name="includePrivateKeys">Indicates whether to include private keys in the conversion.</param>
	/// <returns>A JsonWebKey representing the SecurityKey.</returns>
	public static JsonWebKey ToJsonWebKey(this SecurityKey key, string algorithm, bool includePrivateKeys = false)
	{
		return key switch
		{
			X509SecurityKey { PublicKey: RSA publicKey, PrivateKey: RSA privateKey, Certificate: { } cert }
				=> CreateRsaKey(key, algorithm)
					.Apply(publicKey.ExportParameters(false))
					.Apply(privateKey.ExportParameters(includePrivateKeys))
					.Apply(cert),

            X509SecurityKey { PublicKey: RSA publicKey, Certificate: { } cert } when !includePrivateKeys
				=> CreateRsaKey(key, algorithm)
					.Apply(publicKey.ExportParameters(false))
					.Apply(cert),

			X509SecurityKey { PublicKey: ECDsa publicKey, PrivateKey: ECDsa privateKey, Certificate: { } cert }
				=> CreateEcKey(key, algorithm)
					.Apply(publicKey.ExportParameters(false))
					.Apply(privateKey.ExportParameters(includePrivateKeys))
					.Apply(cert),

            X509SecurityKey { PublicKey: ECDsa publicKey, Certificate: { } cert } when !includePrivateKeys
				=> CreateEcKey(key, algorithm)
					.Apply(publicKey.ExportParameters(false))
					.Apply(cert),

			RsaSecurityKey { Rsa: { } rsa }
				=> CreateRsaKey(key, algorithm).Apply(rsa.ExportParameters(includePrivateKeys)),

			RsaSecurityKey { Parameters: var parameters }
				=> CreateRsaKey(key, algorithm).Apply(parameters),

			ECDsaSecurityKey { ECDsa: { } ecDsa }
				=> CreateEcKey(key, algorithm).Apply(ecDsa.ExportParameters(includePrivateKeys)),

			Microsoft.IdentityModel.Tokens.JsonWebKey msJwk => ConvertFromMicrosoftJsonWebKey(msJwk, includePrivateKeys),

			_ => throw new InvalidOperationException($"The key type {key.GetType().FullName} is not supported"),
		};
	}

	/// <summary>
	/// Creates an RSA JsonWebKey with basic properties populated.
	/// </summary>
	private static RsaJsonWebKey CreateRsaKey(SecurityKey key, string algorithm) => new()
	{
		Usage = key.MapKeyUsage(),
		Algorithm = AlgorithmMapper.MapToOutbound(algorithm),
		KeyId = key.KeyId,
	};

	/// <summary>
	/// Creates an EC JsonWebKey with basic properties populated.
	/// </summary>
	private static EllipticCurveJsonWebKey CreateEcKey(SecurityKey key, string algorithm) => new()
	{
		Usage = key.MapKeyUsage(),
		Algorithm = AlgorithmMapper.MapToOutbound(algorithm),
		KeyId = key.KeyId,
	};

	/// <summary>
	/// Maps the key usage of a SecurityKey to a string representation.
	/// Determines whether the key is used for signing, encryption, or both.
	/// </summary>
	/// <param name="key">The SecurityKey whose usage is to be determined.</param>
	/// <returns>A string representing the usage of the key.</returns>
	private static string MapKeyUsage(this SecurityKey key)
	{
		const string defaultUsage = PublicKeyUsages.Signature;

		if (key is not X509SecurityKey x509Key)
			return defaultUsage;

		var keyUsage = x509Key.Certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
		if (keyUsage == null)
			return defaultUsage;

		var sig = keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature);
		var enc = keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment |
		                                     X509KeyUsageFlags.DataEncipherment);
		return (sig, enc) switch
		{
			(true, true) => PublicKeyUsages.Signature + " " + PublicKeyUsages.Encryption,
			(true, false) => PublicKeyUsages.Signature,
			(false, true) => PublicKeyUsages.Encryption,
			_ => defaultUsage,
		};
	}

	/// <summary>
	/// Applies X509Certificate2 properties to a JsonWebKey.
	/// </summary>
	/// <typeparam name="T">The type of JsonWebKey (must be a subclass).</typeparam>
	/// <param name="jwk">The JsonWebKey to which the certificate properties are to be applied.</param>
	/// <param name="certificate">The X509Certificate2 providing the properties.</param>
	/// <returns>The updated JsonWebKey with applied certificate properties.</returns>
	public static T Apply<T>(this T jwk, X509Certificate2 certificate) where T : JsonWebKey
	{
		jwk.Certificates = [certificate.RawData];
		jwk.Thumbprint = certificate.GetCertHash();
		return jwk;
	}

	/// <summary>
	/// Applies RSA parameters to an RsaJsonWebKey.
	/// </summary>
	/// <param name="jwk">The RsaJsonWebKey to which the RSA parameters are to be applied.</param>
	/// <param name="parameters">The RSAParameters providing the RSA key information.</param>
	/// <returns>The updated RsaJsonWebKey with applied RSA parameters.</returns>
	public static RsaJsonWebKey Apply(this RsaJsonWebKey jwk, RSAParameters parameters)
	{
		jwk.Exponent = parameters.Exponent;
		jwk.Modulus = parameters.Modulus;

		jwk.PrivateExponent = parameters.D;
		jwk.FirstPrimeFactor = parameters.P;
		jwk.SecondPrimeFactor = parameters.Q;
		jwk.FirstFactorCrtExponent = parameters.DP;
		jwk.SecondFactorCrtExponent = parameters.DQ;
		jwk.FirstCrtCoefficient = parameters.InverseQ;

		return jwk;
	}

	/// <summary>
	/// Applies Elliptic Curve parameters to an EllipticCurveJsonWebKey.
	/// </summary>
	/// <param name="jwk">The EllipticCurveJsonWebKey to which the EC parameters are to be applied.</param>
	/// <param name="parameters">The ECParameters providing the Elliptic Curve key information.</param>
	/// <returns>The updated EllipticCurveJsonWebKey with applied Elliptic Curve parameters.</returns>
	public static EllipticCurveJsonWebKey Apply(this EllipticCurveJsonWebKey jwk, ECParameters parameters)
	{
		var curveOid = parameters.Curve.Oid;
		jwk.Curve = curveOid.Value switch
		{
			EllipticCurveOids.P256 => JsonWebKeyECTypes.P256,
			EllipticCurveOids.P384 => JsonWebKeyECTypes.P384,
			EllipticCurveOids.P521 => JsonWebKeyECTypes.P521,
			_ => throw new InvalidOperationException($"The OID [{curveOid.Value}] {curveOid.FriendlyName} is not supported"),
		};

		jwk.X = parameters.Q.X;
		jwk.Y = parameters.Q.Y;

		if (parameters.D != null)
			jwk.PrivateKey = parameters.D;

		return jwk;
	}

	/// <summary>
	/// Converts a Microsoft.IdentityModel.Tokens.JsonWebKey to a custom JsonWebKey.
	/// This method allows the conversion of keys between different JsonWebKey implementations.
	/// </summary>
	/// <param name="key">The Microsoft.IdentityModel.Tokens.JsonWebKey to convert.</param>
	/// <param name="includePrivateKeys">Indicates whether to include private keys in the conversion.</param>
	/// <returns>A JsonWebKey representing the Microsoft.IdentityModel.Tokens.JsonWebKey.</returns>
	private static JsonWebKey ConvertFromMicrosoftJsonWebKey(Microsoft.IdentityModel.Tokens.JsonWebKey key, bool includePrivateKeys = false)
	{
		return key.Kty switch
		{
			JsonWebKeyTypes.Rsa => ConvertRsaFromMicrosoft(key, includePrivateKeys),
			JsonWebKeyTypes.EllipticCurve => ConvertEcFromMicrosoft(key, includePrivateKeys),
			JsonWebKeyTypes.Octet => ConvertSymmetricFromMicrosoft(key, includePrivateKeys),
			_ => throw new InvalidOperationException($"Unsupported key type: {key.Kty}"),
		};
	}

	/// <summary>
	/// Converts an RSA key from Microsoft.IdentityModel.Tokens.JsonWebKey.
	/// </summary>
	private static RsaJsonWebKey ConvertRsaFromMicrosoft(
		Microsoft.IdentityModel.Tokens.JsonWebKey key,
		bool includePrivateKeys)
	{
		var jwk = new RsaJsonWebKey
		{
			Usage = key.Use ?? PublicKeyUsages.Signature,
			Algorithm = key.Alg,
			KeyId = key.Kid,
			Certificates = key.X5c is { Count: > 0 } certificates
				? certificates.Select(HttpServerUtility.UrlTokenDecode).ToArray()
				: null,
			Thumbprint = HttpServerUtility.UrlTokenDecode(key.X5t),
			Exponent = HttpServerUtility.UrlTokenDecode(key.E),
			Modulus = HttpServerUtility.UrlTokenDecode(key.N),
		};

		if (includePrivateKeys)
		{
			jwk.PrivateExponent = HttpServerUtility.UrlTokenDecode(key.D);
			jwk.FirstPrimeFactor = HttpServerUtility.UrlTokenDecode(key.P);
			jwk.SecondPrimeFactor = HttpServerUtility.UrlTokenDecode(key.Q);
			jwk.FirstFactorCrtExponent = HttpServerUtility.UrlTokenDecode(key.DP);
			jwk.SecondFactorCrtExponent = HttpServerUtility.UrlTokenDecode(key.DQ);
			jwk.FirstCrtCoefficient = HttpServerUtility.UrlTokenDecode(key.QI);
		}

		return jwk;
	}

	/// <summary>
	/// Converts an Elliptic Curve key from Microsoft.IdentityModel.Tokens.JsonWebKey.
	/// </summary>
	private static EllipticCurveJsonWebKey ConvertEcFromMicrosoft(Microsoft.IdentityModel.Tokens.JsonWebKey key, bool includePrivateKeys)
	{
		var jwk = new EllipticCurveJsonWebKey
		{
			Usage = key.Use ?? PublicKeyUsages.Signature,
			Algorithm = key.Alg,
			KeyId = key.Kid,
			Certificates = key.X5c is { Count: > 0 } certificates
				? certificates.Select(HttpServerUtility.UrlTokenDecode).ToArray()
				: null,
			Thumbprint = HttpServerUtility.UrlTokenDecode(key.X5t),
			Curve = key.Crv,
			X = HttpServerUtility.UrlTokenDecode(key.X),
			Y = HttpServerUtility.UrlTokenDecode(key.Y),
		};

		if (includePrivateKeys)
		{
			jwk.PrivateKey = HttpServerUtility.UrlTokenDecode(key.D);
		}

		return jwk;
	}

	/// <summary>
	/// Converts a symmetric key from Microsoft.IdentityModel.Tokens.JsonWebKey.
	/// </summary>
	private static OctetJsonWebKey ConvertSymmetricFromMicrosoft(Microsoft.IdentityModel.Tokens.JsonWebKey key, bool includePrivateKeys)
	{
		var jwk = new OctetJsonWebKey
		{
			Usage = key.Use ?? PublicKeyUsages.Signature,
			Algorithm = key.Alg,
			KeyId = key.Kid,
		};

		if (includePrivateKeys)
		{
			jwk.KeyValue = HttpServerUtility.UrlTokenDecode(key.K);
		}

		return jwk;
	}

	/// <summary>
	/// Converts an RsaJsonWebKey to an RSA object, which represents an RSA public and private key pair or just a public key.
	/// </summary>
	/// <param name="key">The RsaJsonWebKey to be converted.</param>
	/// <returns>An RSA object based on the provided RsaJsonWebKey.</returns>
	public static RSA ToRsa(this RsaJsonWebKey key)
	{
		var rsa = RSA.Create();
		rsa.ImportParameters(key.ToRsaParameters());
		return rsa;
	}

	/// <summary>
	/// Converts an RsaJsonWebKey to RSAParameters, which represent the key parameters used in RSA cryptographic operations.
	/// </summary>
	/// <param name="key">The RsaJsonWebKey to be converted.</param>
	/// <returns>An RSAParameters object based on the provided RsaJsonWebKey.</returns>
	public static RSAParameters ToRsaParameters(this RsaJsonWebKey key) => new()
	{
		Modulus = key.Modulus,
		Exponent = key.Exponent,
		D = key.PrivateExponent,
		P = key.FirstPrimeFactor,
		Q = key.SecondPrimeFactor,
		DP = key.FirstFactorCrtExponent,
		DQ = key.SecondFactorCrtExponent,
		InverseQ = key.FirstCrtCoefficient,
	};
}
