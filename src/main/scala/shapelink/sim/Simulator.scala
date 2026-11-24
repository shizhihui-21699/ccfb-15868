package shapelink.sim

import shapelink.core.*
import shapelink.shape.*
import shapelink.ops.ShaperMetrics
import scala.collection.mutable

/** Exactly what an on-path observer can see. Note what is *absent*: no message sizes,
  * no message counts, no plaintext structure. Just (time, size) per cell -- and size is
  * constant by construction.
  */
final case class WireCell(atNanos: Long, bytes: Int, seq: Long)

final case class WireTrace(cells: Vector[WireCell]):
  def distinctSizes: Set[Int] = cells.iterator.map(_.bytes).toSet
  def durationNanos: Long = if cells.isEmpty then 0L else cells.last.atNanos - cells.head.atNanos
  def totalBytes: Long = cells.iterator.map(_.bytes.toLong).sum

/** Ground truth, kept for evaluation only -- never available to the observer. */
final case class MessageTruth(
    seq: Long,
    submitAt: Long,
    completeAt: Long,
    cls: TxnClass,
    amount: AmountBucket,
    vip: Boolean,
    bytes: Int
):
  def latencyNanos: Long = completeAt - submitAt

final case class SimResult(
    trace: WireTrace,
    truth: Vector[MessageTruth],
    metrics: ShaperMetrics,
    deliveryErrors: Int,
    messagesDelivered: Int
)

object Simulator:

  /** Run a workload through the shaper and a real receiver on a virtual clock.
    *
    * The receiver decrypts and reassembles every cell, so a bug that drops, duplicates
    * or corrupts a message fails here loudly rather than in production.
    */
  def run(cfg: ShaperConfig, workload: WorkloadConfig, seed: Long): SimResult =
    val messages = TrafficModel.generate(workload, seed)
    val key = Crypto.keyFromSeed(seed * 31L + 7L)
    val shaper = new Shaper(cfg, key, 1L, new Rng(seed * 17L + 3L))

    val cells = Vector.newBuilder[WireCell]
    var deliveryErrors = 0
    var delivered = 0
    val reasm = new Reassembler
    val completeAt = mutable.HashMap.empty[Long, Long]
    shaper.onMessageComplete = (msgId, at) => completeAt(msgId) = at

    def drain(emitted: Vector[Emitted]): Unit =
      emitted.foreach { e =>
        cells += WireCell(e.at, e.bytes.length, Wire.parseHeader(e.bytes).map(_.seq).getOrElse(-1L))
        Wire.openCell(key, e.bytes) match
          case None => deliveryErrors += 1
          case Some((_, plaintext)) =>
            CellCodec.unpack(plaintext) match
              case Left(_) => deliveryErrors += 1
              case Right(recs) =>
                recs.foreach { r =>
                  if reasm.offer(r).isDefined then delivered += 1
                }
      }

    val n = messages.length
    var i = 0
    var now = 0L
    var guard = 0L
    while i < n || shaper.pendingRecordCount > 0 do
      guard += 1
      if guard > 500_000_000L then throw new RuntimeException("simulation did not converge")
      val nextSubmit = if i < n then messages(i).atNanos else Long.MaxValue
      val wake = shaper.nextWakeup(now)
      val t = math.min(nextSubmit, wake)
      if t == Long.MaxValue then
        if shaper.pendingRecordCount > 0 then drain(shaper.step(now)) else i = n
      else
        now = t
        while i < n && messages(i).atNanos <= now do
          val m = messages(i)
          shaper.submit(m.atNanos, m.seq, m.payload, TxnClass.serviceClass(m.cls))
          i += 1
        drain(shaper.step(now))

    // Flush anything the deadline logic is still holding.
    val flushAt = if completeAt.size < n then now + cfg.maxHoldNanos * 2 else now
    if shaper.pendingRecordCount > 0 then drain(shaper.step(flushAt))

    val truth = messages.map { m =>
      val done = completeAt.getOrElse(m.seq, m.atNanos)
      MessageTruth(m.seq, m.atNanos, done, m.cls, m.amount, m.vip, m.payload.length)
    }

    SimResult(WireTrace(cells.result()), truth, shaper.metrics, deliveryErrors, delivered)
