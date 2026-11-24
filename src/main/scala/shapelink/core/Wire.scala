package shapelink.core

import java.nio.ByteBuffer

/** Fixed-size transport cell.
  *
  * THE CENTRAL DESIGN CONSTRAINT
  * -----------------------------
  * The whole point of this layer is that an observer on the network learns *nothing*
  * from a cell's structure. If the wire format carried a length field, a record count,
  * or a "padding amount", padding would be self-defeating: the header would announce
  * exactly how much was padded, and the original length would be recoverable.
  *
  * Therefore every cell on the wire is exactly `cellSize` bytes and the public header
  * is a fixed 14 bytes with no variable-length content:
  *
  *   offset  size  field
  *   0       1     version
  *   1       1     flags      (reserved, currently always 0)
  *   2       8     epoch      (u64, key epoch; also the nonce prefix)
  *   10      4     seq        (u32, monotonic per direction; nonce suffix)
  *                 14 bytes header, then AEAD ciphertext (plaintext capacity + 16 tag)
  *
  * Everything else -- how many application messages a cell carries, how much of it is
  * padding, whether it is cover traffic -- lives inside the AEAD plaintext and is
  * indistinguishable from random bytes to anyone without the key.
  */
object Wire:
  val Version: Byte = 1
  val HeaderLen = 14
  /** Header + GCM tag: bytes per cell not available to the inner record layer. */
  val Overhead = HeaderLen + Crypto.TagLen
  /** seq is a u32 but capped so (epoch, seq) can never repeat within an epoch. */
  val MaxSeq = 0x7FFFFFFFL

  def capacity(cellSize: Int): Int = cellSize - Overhead

  def nonce(epoch: Long, seq: Long): Array[Byte] =
    val n = Array.ofDim[Byte](Crypto.NonceLen)
    val bb = ByteBuffer.wrap(n)
    bb.putLong(epoch)
    bb.putInt(seq.toInt)
    n

  def headerBytes(epoch: Long, seq: Long, flags: Byte = 0): Array[Byte] =
    val h = Array.ofDim[Byte](HeaderLen)
    val bb = ByteBuffer.wrap(h)
    bb.put(Version)
    bb.put(flags)
    bb.putLong(epoch)
    bb.putInt(seq.toInt)
    h

  final case class Header(version: Byte, flags: Byte, epoch: Long, seq: Long)

  def parseHeader(b: Array[Byte]): Option[Header] =
    if b.length < HeaderLen then None
    else
      val bb = ByteBuffer.wrap(b)
      val v = bb.get()
      val f = bb.get()
      val e = bb.getLong()
      val s = bb.getInt()
      if v != Version then None else Some(Header(v, f, e, s & 0xFFFFFFFFL))

  def sealCell(key: Array[Byte], epoch: Long, seq: Long, plaintext: Array[Byte], cellSize: Int): Array[Byte] =
    val cap = capacity(cellSize)
    require(plaintext.length <= cap, s"plaintext ${plaintext.length} exceeds capacity $cap")
    val hdr = headerBytes(epoch, seq)
    val ct = Crypto.seal(key, nonce(epoch, seq), hdr, plaintext)
    // Cell size is fixed, so pad the *ciphertext* only if the caller under-filled.
    // Callers always pass a full-capacity plaintext, so this is a no-op safeguard.
    require(ct.length == cap + Crypto.TagLen, s"cell body ${ct.length} != ${cap + Crypto.TagLen}")
    val out = Array.ofDim[Byte](cellSize)
    System.arraycopy(hdr, 0, out, 0, HeaderLen)
    System.arraycopy(ct, 0, out, HeaderLen, ct.length)
    out

  def openCell(key: Array[Byte], bytes: Array[Byte]): Option[(Header, Array[Byte])] =
    parseHeader(bytes).flatMap { h =>
      val ct = new Array[Byte](bytes.length - HeaderLen)
      System.arraycopy(bytes, HeaderLen, ct, 0, ct.length)
      Crypto.open(key, nonce(h.epoch, h.seq), headerBytes(h.epoch, h.seq, h.flags), ct).map(p => (h, p))
    }
