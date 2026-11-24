package shapelink.core

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}

/** AES-256-GCM helpers.
  *
  * Key material is supplied by the transport's key schedule; this object only performs
  * the per-cell AEAD. The nonce is derived deterministically from (epoch, seq) so no
  * nonce bytes travel on the wire, and the fixed public header is bound as AAD so a
  * middlebox cannot renumber, reorder-into-splice or truncate cells without detection.
  */
object Crypto:
  val TagLen = 16
  val NonceLen = 12

  /** Deterministic key derivation for reproducible experiments (NOT for production). */
  def keyFromSeed(seed: Long): Array[Byte] =
    val k = Array.ofDim[Byte](32)
    new Rng(seed).nextBytes(k)
    k

  /** Production key generation. */
  def freshKey(): Array[Byte] =
    val k = Array.ofDim[Byte](32)
    SecureRandom.getInstanceStrong.nextBytes(k)
    k

  private val cipherPool = new ThreadLocal[Cipher]:
    override def initialValue(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")

  private def cipher(key: Array[Byte], mode: Int, nonce: Array[Byte], aad: Array[Byte]): Cipher =
    val c = cipherPool.get()
    c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TagLen * 8, nonce))
    if aad != null && aad.length > 0 then c.updateAAD(aad)
    c

  /** Returns ciphertext || tag. */
  def seal(key: Array[Byte], nonce: Array[Byte], aad: Array[Byte], plaintext: Array[Byte]): Array[Byte] =
    cipher(key, Cipher.ENCRYPT_MODE, nonce, aad).doFinal(plaintext)

  /** None when authentication fails (tamper, wrong key, wrong epoch/seq). */
  def open(key: Array[Byte], nonce: Array[Byte], aad: Array[Byte], ct: Array[Byte]): Option[Array[Byte]] =
    try Some(cipher(key, Cipher.DECRYPT_MODE, nonce, aad).doFinal(ct))
    catch
      case _: javax.crypto.AEADBadTagException => None
      case _: java.security.GeneralSecurityException => None
