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
	{
		return jsonWebKey.Algorithm switch
		{
			SigningAlgorithms.RS256 => new SigningCredentials(jsonWebKey.ToSecurityKey(), SigningAlgorithms.RS256),
			_ => throw new InvalidOperationException($"Not supported algorithm: {jsonWebKey.Algorithm}"),
		};
	}

	/// <summary>
	/// Converts a JsonWebKey to an RsaSecurityKey used in RSA cryptographic operations.
	/// </summary>
	/// <param name="jsonWebKey">The JsonWebKey to convert.</param>
	/// <returns>RsaSecurityKey based on the provided JsonWebKey.</returns>
	public static RsaSecurityKey ToSecurityKey(this JsonWebKey jsonWebKey)
	{
		return new RsaSecurityKey(jsonWebKey.ToRsa()) { KeyId = jsonWebKey.KeyId };
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
			SigningAlgorithms.RS256 => new EncryptingCredentials(
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
		=> new X509SecurityKey(certificate).ToJsonWebKey(SecurityAlgorithms.RsaSha256, includePrivateKeys);

	/// <summary>
	/// Converts a SecurityKey to a JsonWebKey with a specified algorithm. The private keys can be optionally included.
	/// </summary>
	/// <param name="key">The SecurityKey to convert.</param>
	/// <param name="algorithm">The algorithm to be used with the key.</param>
	/// <param name="includePrivateKeys">Indicates whether to include private keys in the conversion.</param>
	/// <returns>A JsonWebKey representing the SecurityKey.</returns>
	public static JsonWebKey ToJsonWebKey(this SecurityKey key, string algorithm, bool includePrivateKeys = false)
	{
		// TODO Move it to a virtual method of generic Credentials class with specific implementations in derived classes
		var jwk = new JsonWebKey
		{
			Usage = key.MapKeyUsage(),
			Algorithm = AlgorithmMapper.MapToOutbound(algorithm),
			KeyId = key.KeyId,
		};

		return key switch
		{
			X509SecurityKey { PublicKey: RSA publicKey, PrivateKey: RSA privateKey, Certificate: { } cert }
				=> jwk
					.Apply(publicKey.ExportParameters(false))
					.Apply(privateKey.ExportParameters(includePrivateKeys))
					.Apply(cert),
			
            X509SecurityKey { PublicKey: RSA publicKey, Certificate: { } cert } when !includePrivateKeys
				=> jwk
					.Apply(publicKey.ExportParameters(false))
					.Apply(cert),

			X509SecurityKey { PublicKey: ECDsa publicKey, PrivateKey: ECDsa privateKey, Certificate: { } cert }
				=> jwk
					.Apply(publicKey.ExportParameters(false))
					.Apply(privateKey.ExportParameters(includePrivateKeys))
					.Apply(cert),
            
            X509SecurityKey { PublicKey: ECDsa publicKey, Certificate: { } cert } when !includePrivateKeys
				=> jwk
					.Apply(publicKey.ExportParameters(false))
					.Apply(cert),

			RsaSecurityKey { Rsa: { } rsa } => jwk.Apply(rsa.ExportParameters(includePrivateKeys)),
			RsaSecurityKey { Parameters: var parameters } => jwk.Apply(parameters),

			ECDsaSecurityKey { ECDsa: { } ecDsa } => jwk.Apply(ecDsa.ExportParameters(includePrivateKeys)),

			Microsoft.IdentityModel.Tokens.JsonWebKey jsonWebKey => jwk.Apply(jsonWebKey, includePrivateKeys),

			_ => throw new InvalidOperationException($"The key type {key.GetType().FullName} is not supported"),
		};
	}

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
	/// <param name="jwk">The JsonWebKey to which the certificate properties are to be applied.</param>
	/// <param name="certificate">The X509Certificate2 providing the properties.</param>
	/// <returns>The updated JsonWebKey with applied certificate properties.</returns>
	public static JsonWebKey Apply(this JsonWebKey jwk, X509Certificate2 certificate)
	{
		jwk.Certificates = new[] { certificate.RawData };
		jwk.Thumbprint = certificate.GetCertHash();
		return jwk;
	}

	/// <summary>
	/// Applies RSA parameters to a JsonWebKey.
	/// </summary>
	/// <param name="jwk">The JsonWebKey to which the RSA parameters are to be applied.</param>
	/// <param name="parameters">The RSAParameters providing the RSA key information.</param>
	/// <returns>The updated JsonWebKey with applied RSA parameters.</returns>
	public static JsonWebKey Apply(this JsonWebKey jwk, RSAParameters parameters)
	{
		jwk.KeyType = JsonWebKeyTypes.Rsa;
		jwk.RsaExponent = parameters.Exponent;
		jwk.RsaModulus = parameters.Modulus;

		jwk.PrivateKey = parameters.D;
		jwk.FirstPrimeFactor = parameters.P;
		jwk.SecondPrimeFactor = parameters.Q;
		jwk.FirstFactorCrtExponent = parameters.DP;
		jwk.SecondFactorCrtExponent = parameters.DQ;
		jwk.FirstCrtCoefficient = parameters.InverseQ;

		return jwk;
	}

	private static class EllipticalCurveOids
	{
		public const string P256 = "1.2.840.10045.3.1.7";
		public const string P384 = "1.3.132.0.34";
		public const string P521 = "1.3.132.0.35";
	}

	/// <summary>
	/// Applies Elliptic Curve parameters to a JsonWebKey.
	/// </summary>
	/// <param name="jwk">The JsonWebKey to which the EC parameters are to be applied.</param>
	/// <param name="parameters">The ECParameters providing the Elliptic Curve key information.</param>
	/// <returns>The updated JsonWebKey with applied Elliptic Curve parameters.</returns>
	private static JsonWebKey Apply(this JsonWebKey jwk, ECParameters parameters)
	{
		jwk.KeyType = JsonWebKeyTypes.EllipticalCurve;

		var curveOid = parameters.Curve.Oid;
		jwk.EllipticalCurveType = curveOid.Value switch
		{
			EllipticalCurveOids.P256 => JsonWebKeyECTypes.P256,
			EllipticalCurveOids.P384 => JsonWebKeyECTypes.P384,
			EllipticalCurveOids.P521 => JsonWebKeyECTypes.P521,
			_ => throw new InvalidOperationException($"The OID [{curveOid.Value}] {curveOid.FriendlyName} is not supported"),
		};

		jwk.EllipticalCurvePointX = parameters.Q.X;
		jwk.EllipticalCurvePointY = parameters.Q.Y;

		if (parameters.D != null) jwk.PrivateKey = parameters.D;

		return jwk;
	}

	/// <summary>
	/// Converts a Microsoft.IdentityModel.Tokens.JsonWebKey to a custom JsonWebKey.
	/// This method allows the conversion of keys between different JsonWebKey implementations.
	/// </summary>
	/// <param name="jwk">The JsonWebKey to be converted.</param>
	/// <param name="key">The Microsoft.IdentityModel.Tokens.JsonWebKey to convert.</param>
	/// <param name="includePrivateKeys">Indicates whether to include private keys in the conversion.</param>
	/// <returns>A JsonWebKey representing the Microsoft.IdentityModel.Tokens.JsonWebKey.</returns>
	private static JsonWebKey Apply(this JsonWebKey jwk, Microsoft.IdentityModel.Tokens.JsonWebKey key, bool includePrivateKeys = false)
	{
		jwk.KeyType = key.Kty;
		jwk.Usage = key.Use ?? PublicKeyUsages.Signature;
		jwk.Algorithm = key.Alg;
		jwk.KeyId = key.Kid;

		jwk.Certificates = key.X5c is { Count: > 0 } certificates ? certificates.Select(HttpServerUtility.UrlTokenDecode).ToArray() : null;
		jwk.Thumbprint = HttpServerUtility.UrlTokenDecode(key.X5t);

		jwk.RsaExponent = HttpServerUtility.UrlTokenDecode(key.E);
		jwk.RsaModulus = HttpServerUtility.UrlTokenDecode(key.N);

		jwk.EllipticalCurveType = key.Crv;
		jwk.EllipticalCurvePointX = HttpServerUtility.UrlTokenDecode(key.X);
		jwk.EllipticalCurvePointY = HttpServerUtility.UrlTokenDecode(key.Y);

		if (includePrivateKeys)
		{
			jwk.PrivateKey = HttpServerUtility.UrlTokenDecode(key.D);
			jwk.FirstPrimeFactor = HttpServerUtility.UrlTokenDecode(key.P);
			jwk.SecondPrimeFactor = HttpServerUtility.UrlTokenDecode(key.Q);
			jwk.FirstFactorCrtExponent = HttpServerUtility.UrlTokenDecode(key.DP);
			jwk.SecondFactorCrtExponent = HttpServerUtility.UrlTokenDecode(key.DQ);
			jwk.FirstCrtCoefficient = HttpServerUtility.UrlTokenDecode(key.QI);
		}
		return jwk;
	}

	/// <summary>
	/// Converts a JsonWebKey to an RSA object, which represents an RSA public and private key pair or just a public key.
	/// </summary>
	/// <param name="key">The JsonWebKey to be converted.</param>
	/// <returns>An RSA object based on the provided JsonWebKey.</returns>
	public static RSA ToRsa(this JsonWebKey key)
	{
		var rsa = RSA.Create();
		rsa.ImportParameters(key.ToRsaParameters());
		return rsa;
	}

	/// <summary>
	/// Converts a JsonWebKey to RSAParameters, which represent the key parameters used in RSA cryptographic operations.
	/// </summary>
	/// <param name="key">The JsonWebKey to be converted.</param>
	/// <returns>An RSAParameters object based on the provided JsonWebKey.</returns>
	public static RSAParameters ToRsaParameters(this JsonWebKey key) => new()
	{
		Modulus = key.RsaModulus,
		Exponent = key.RsaExponent,
		D = key.PrivateKey,
		P = key.FirstPrimeFactor,
		Q = key.SecondPrimeFactor,
		DP = key.FirstFactorCrtExponent,
		DQ = key.SecondFactorCrtExponent,
		InverseQ = key.FirstCrtCoefficient,
	};
}
