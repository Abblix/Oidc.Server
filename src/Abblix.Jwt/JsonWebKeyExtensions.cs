// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Abblix.Jwt;

/// <summary>
/// Provides extension methods for the JsonWebKey model to simplify the process of populating its properties from different sources.
/// These methods enable easy conversion between JsonWebKey and various cryptographic representations.
/// </summary>
public static class JsonWebKeyExtensions
{
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

			var jwk = new EllipticCurveJsonWebKey
			{
				Usage = certificate.GetKeyUsage(),
				KeyId = certificate.Thumbprint,
			}
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

			var jwk = new RsaJsonWebKey
			{
				Usage = certificate.GetKeyUsage(),
				KeyId = certificate.Thumbprint,
			}.Apply(rsaPublicKey.ExportParameters(false)).Apply(certificate);

			if (rsaPrivateKey != null)
			{
				jwk = jwk.Apply(rsaPrivateKey.ExportParameters(true));
			}

			return jwk;
		}

		throw new InvalidOperationException($"Certificate does not contain a supported public key algorithm");
	}

	/// <summary>
	/// Derives the JWK <c>use</c> value from a certificate's Key Usage extension. A certificate that permits both
	/// signing and encryption maps to no <c>use</c> (<c>null</c>): RFC 7517 §4.2 makes <c>use</c> a single value,
	/// so an unrestricted key is expressed by omitting <c>use</c>, never by a multi-valued string. A certificate
	/// with no Key Usage extension defaults to signing.
	/// </summary>
	private static string? GetKeyUsage(this X509Certificate2 certificate)
	{
		const string defaultUsage = PublicKeyUsages.Signature;

		var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
		if (keyUsage == null)
			return defaultUsage;

		var sig = keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature);

		// Either encipherment flag marks an encryption key. HasFlag(A | B) would demand both flags, so test the bits.
		var enc =
			keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment) ||
			keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DataEncipherment);

		return (sig, enc) switch
		{
			(true, true) => null, // permits both: omit use per RFC 7517 §4.2, never a multi-valued "sig enc"
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
			EllipticCurveOids.P256 => EllipticCurveTypes.P256,
			EllipticCurveOids.P384 => EllipticCurveTypes.P384,
			EllipticCurveOids.P521 => EllipticCurveTypes.P521,
			_ => throw new InvalidOperationException($"The OID [{curveOid.Value}] {curveOid.FriendlyName} is not supported"),
		};

		jwk.Algorithm ??= curveOid.Value switch
		{
			EllipticCurveOids.P256 => SigningAlgorithms.ES256,
			EllipticCurveOids.P384 => SigningAlgorithms.ES384,
			EllipticCurveOids.P521 => SigningAlgorithms.ES512,
			_ => throw new InvalidOperationException($"The OID [{curveOid.Value}] {curveOid.FriendlyName} is not supported"),
		};

		jwk.X = parameters.Q.X;
		jwk.Y = parameters.Q.Y;

		if (parameters.D != null)
			jwk.PrivateKey = parameters.D;

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

	/// <summary>
	/// Converts an EllipticCurveJsonWebKey to an ECDsa object,
	/// which represents an ECDSA public and private key pair or just a public key.
	/// </summary>
	/// <param name="key">The EllipticCurveJsonWebKey to be converted.</param>
	/// <returns>An ECDsa object based on the provided EllipticCurveJsonWebKey.</returns>
	public static ECDsa ToEcdsa(this EllipticCurveJsonWebKey key)
	{
		var ecdsa = ECDsa.Create();
		ecdsa.ImportParameters(key.ToEcParameters());
		return ecdsa;
	}

	/// <summary>
	/// Converts an EllipticCurveJsonWebKey to an ECDiffieHellman object for ECDH key agreement
	/// operations (e.g. the ECDH-ES family of JWE key management algorithms).
	/// </summary>
	/// <param name="key">The EllipticCurveJsonWebKey to be converted.</param>
	/// <returns>An ECDiffieHellman object based on the provided EllipticCurveJsonWebKey.</returns>
	public static ECDiffieHellman ToEcdh(this EllipticCurveJsonWebKey key)
	{
		var ecdh = ECDiffieHellman.Create();
		ecdh.ImportParameters(key.ToEcParameters());
		return ecdh;
	}

	/// <summary>
	/// Converts an EllipticCurveJsonWebKey to ECParameters,
	/// which represent the key parameters used in ECDSA cryptographic operations.
	/// Supports P-256, P-384, and P-521 curves as defined in NIST standards.
	/// </summary>
	/// <param name="key">The EllipticCurveJsonWebKey to be converted.</param>
	/// <returns>An ECParameters object based on the provided EllipticCurveJsonWebKey.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the curve type is not supported.</exception>
	public static ECParameters ToEcParameters(this EllipticCurveJsonWebKey key)
	{
		var curve = key.Curve switch
		{
			EllipticCurveTypes.P256 => ECCurve.NamedCurves.nistP256,
			EllipticCurveTypes.P384 => ECCurve.NamedCurves.nistP384,
			EllipticCurveTypes.P521 => ECCurve.NamedCurves.nistP521,
			_ => throw new InvalidOperationException(
				$"Unsupported elliptic curve: {key.Curve}. " +
				$"Supported curves: {EllipticCurveTypes.P256}, {EllipticCurveTypes.P384}, {EllipticCurveTypes.P521}"),
		};

		return new ECParameters
		{
			Curve = curve,
			Q = new ECPoint
			{
				X = key.X ?? throw new InvalidOperationException("X coordinate is required for elliptic curve key"),
				Y = key.Y ?? throw new InvalidOperationException("Y coordinate is required for elliptic curve key"),
			},
			D = key.PrivateKey, // Optional private key component
		};
	}

	/// <summary>
	/// Whether this key can carry out the given algorithm - JWS signing or JWE key management - judged by the
	/// key's own material rather than by what it declares.
	/// </summary>
	/// <remarks>
	/// RFC 7517 section 4.4 makes <c>alg</c> OPTIONAL, so a key may simply not say what it is for - and a key
	/// imported from a certificate never does. Such a key is not "unknown", it is answerable: RFC 7518 section 3.1
	/// binds each algorithm to a key type, and section 3.4 binds each ECDSA algorithm to one curve. Asking the
	/// material is therefore exact, and it is the only question that matters at the point of use, since a
	/// declaration is a claim while the material is the fact.
	/// </remarks>
	/// <param name="key">The key to test.</param>
	/// <param name="algorithm">The JWS algorithm the caller needs.</param>
	/// <returns>True when the key's type, and for ECDSA its curve, match what the algorithm requires.</returns>
	public static bool SupportsAlgorithm(this JsonWebKey key, string algorithm) => algorithm switch
	{
		SigningAlgorithms.RS256 or
		SigningAlgorithms.RS384 or
		SigningAlgorithms.RS512 or

		SigningAlgorithms.PS256 or
		SigningAlgorithms.PS384 or
		SigningAlgorithms.PS512 => key.KeyType == JsonWebKeyTypes.Rsa,

		SigningAlgorithms.ES256 => key.IsCurve(EllipticCurveTypes.P256),
		SigningAlgorithms.ES384 => key.IsCurve(EllipticCurveTypes.P384),
		SigningAlgorithms.ES512 => key.IsCurve(EllipticCurveTypes.P521),

		SigningAlgorithms.HS256 or
		SigningAlgorithms.HS384 or
		SigningAlgorithms.HS512 => key.KeyType == JsonWebKeyTypes.Octet,

		// JWE key management, RFC 7518 section 4.1. The same question, asked of the recipient's key.
		EncryptionAlgorithms.KeyManagement.Rsa1_5 or
		EncryptionAlgorithms.KeyManagement.RsaOaep or
		EncryptionAlgorithms.KeyManagement.RsaOaep256 => key.KeyType == JsonWebKeyTypes.Rsa,

		// Key agreement needs a curve, and any of the three will do: unlike ECDSA, the algorithm name does
		// not pin one, so the curve is carried in the ephemeral key instead.
		EncryptionAlgorithms.KeyManagement.EcdhEs or
		EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW or
		EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW or
		EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW => key.KeyType == JsonWebKeyTypes.EllipticCurve,

		EncryptionAlgorithms.KeyManagement.Aes128KW or
		EncryptionAlgorithms.KeyManagement.Aes192KW or
		EncryptionAlgorithms.KeyManagement.Aes256KW or
		EncryptionAlgorithms.KeyManagement.Aes128Gcmkw or
		EncryptionAlgorithms.KeyManagement.Aes192Gcmkw or
		EncryptionAlgorithms.KeyManagement.Aes256Gcmkw or
		EncryptionAlgorithms.KeyManagement.Dir or
		EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW or
		EncryptionAlgorithms.KeyManagement.Pbes2HmacSha384Aes192KW or
		EncryptionAlgorithms.KeyManagement.Pbes2HmacSha512Aes256KW => key.KeyType == JsonWebKeyTypes.Octet,

		// "none" carries no key, and an unregistered name is one this library cannot perform: in both cases
		// no key qualifies, which is the answer rather than a reason to guess.
		_ => false,
	};

	/// <summary>Whether the key is an elliptic-curve key on exactly the named curve.</summary>
	private static bool IsCurve(this JsonWebKey key, string curve)
		=> key is EllipticCurveJsonWebKey ec && ec.Curve == curve;
}
