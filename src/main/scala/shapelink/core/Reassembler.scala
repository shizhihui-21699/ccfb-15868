package shapelink.core

import scala.collection.mutable

/** Reassembles fragmented messages from record fragments.
  *
  * Fragments carry (msgId, fragIdx, fragCount) inside the AEAD plaintext, so the
  * receiver can rebuild a message that was spread over several cells without the
  * network ever knowing how many fragments it had or how large it was.
  */
final class Reassembler:
  private final case class Partial(fragCount: Int, parts: mutable.Map[Int, Array[Byte]]):
    def size: Int = parts.valuesIterator.map(_.length).sum

  private val partials = mutable.HashMap.empty[Long, Partial]
  private var completed = 0L
  private var dropped = 0L
  private var maxPartialBytes = 0L
  /** Guard against memory exhaustion from a malicious peer sending endless fragments. */
  var maxInFlightBytes: Long = 64L << 20

  def completedMessages: Long = completed
  def incompleteMessages: Int = partials.size
  def droppedMessages: Long = dropped
  def inFlightBytes: Long = partials.valuesIterator.map(p => p.size.toLong).sum

  /** Feed one fragment. Returns the full message bytes when this fragment completes it. */
  def offer(rec: Record): Option[Array[Byte]] =
    if rec.kind == RecKind.Cover then None
    else if rec.fragCount <= 0 then { dropped += 1; None }
    else if rec.fragIdx >= rec.fragCount then { dropped += 1; None }
    else if rec.fragCount == 1 then
      if rec.fragIdx != 0 then { dropped += 1; None }
      else { completed += 1; Some(rec.payload) }
    else
      val p = partials.getOrElseUpdate(rec.msgId, Partial(rec.fragCount, mutable.HashMap.empty))
      if p.fragCount != rec.fragCount then
        partials.remove(rec.msgId)
        dropped += 1
        None
      else if p.parts.contains(rec.fragIdx) then
        dropped += 1 // duplicate fragment; ignore
        None
      else
        p.parts(rec.fragIdx) = rec.payload
        maxPartialBytes = math.max(maxPartialBytes, inFlightBytes)
        if inFlightBytes > maxInFlightBytes then
          // Bound memory: drop the oldest partial whose message is not yet complete.
          partials.remove(rec.msgId)
          dropped += 1
          None
        else if p.parts.size == p.fragCount then
          var total = 0
          var i = 0
          while i < p.fragCount do { total += p.parts(i).length; i += 1 }
          val out = Array.ofDim[Byte](total)
          var off = 0
          i = 0
          while i < p.fragCount do
            val b = p.parts(i)
            System.arraycopy(b, 0, out, off, b.length)
            off += b.length
            i += 1
          partials.remove(rec.msgId)
          completed += 1
          Some(out)
        else None
