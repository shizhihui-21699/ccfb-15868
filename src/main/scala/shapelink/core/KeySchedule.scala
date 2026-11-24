package shapelink.core

import java.nio.ByteBuffer

/** Key schedule with epoch rotation.
  *
  * Cells bind (epoch, seq) into the nonce and into the AEAD's AAD. Two consequences that
  * matter operationally:
  *
  *  - A key must never be used for two cells with the same (epoch, seq). The epoch is
  *    rotated before `seq` can wrap, and the JDK's GCM implementation refuses to reuse
  *    an IV, so a bug here fails loudly rather than silently weakening confidentiality.
  *  - Rotation is by epoch rather than by wall clock, so it is reproducible in tests and
  *    does not depend on both endpoints agreeing about time.
  *
  * Rotation is scheduled by cell count (not time) so it is deterministic: after
  * `rotateAfterCells` cells the sender moves to the next epoch, and the receiver follows
  * the epoch carried in each header. Cells from the previous epoch remain openable for a
  * bounded grace window, because reordering on the wire is normal.
  */
final class KeySchedule(
    masterKey: Array[Byte],
    initialEpoch: Long = 1L,
    val rotateAfterCells: Long = Wire.MaxSeq.toLong
):
  private var current = initialEpoch
  private var cellsInEpoch = 0L
  private val byEpoch = scala.collection.mutable.HashMap.empty[Long, Array[Byte]]

  byEpoch(current) = derive(initialEpoch)

  /** Per-epoch key: HKDF-like extraction from the master key and the epoch number. */
  private def derive(epoch: Long): Array[Byte] =
    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
    mac.init(new javax.crypto.spec.SecretKeySpec(masterKey, "HmacSHA256"))
    val eb = ByteBuffer.allocate(8).putLong(epoch).array()
    mac.update("shapelink-epoch-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII))
    mac.update(eb)
    mac.doFinal()

  def epoch: Long = current
  def keyFor(epoch: Long): Option[Array[Byte]] = byEpoch.get(epoch)

  /** Called after a cell is sealed. Returns the new epoch if a rotation happened. */
  def onSealed(): Option[Long] =
    cellsInEpoch += 1
    if cellsInEpoch >= rotateAfterCells then
      current += 1
      cellsInEpoch = 0L
      byEpoch(current) = derive(current)
      // Keep only the current and previous epoch: bounded key retention.
      byEpoch.keys.filter(e => e < current - 1).toList.foreach(byEpoch.remove)
      Some(current)
    else None

  /** Register an epoch seen on the wire so its cells can be opened. */
  def acceptEpoch(e: Long): Unit =
    if !byEpoch.contains(e) && e <= current + 1 && e >= current - 1 then
      byEpoch(e) = derive(e)
