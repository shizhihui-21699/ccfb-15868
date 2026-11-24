package shapelink.shape

import shapelink.core.*
import shapelink.ops.ShaperMetrics
import scala.collection.mutable

/** One cell leaving the shaper. `records`/`messageBytes` are provenance for metrics and
  * are never sent on the wire. */
final case class Emitted(at: Long, bytes: Array[Byte], isCover: Boolean, records: Seq[Record], messageBytes: Int)

/** Traffic shaper: application messages in, fixed-size encrypted cells out.
  *
  * A deterministic state machine driven by an explicit virtual clock, so the same code
  * runs in the simulator (clock = counter) and in the live transport (clock = nanoTime).
  * Determinism is what makes an evaluation reproducible and auditable afterwards.
  *
  * TWO QUEUES, STRICT PRIORITY
  * ---------------------------
  * There is one queue per service class, and interactive always wins. This is not a
  * detail: with a single FIFO, a settlement burst sits at the head and every retail
  * message queues behind it. Measured, that took interactive p99 from a 25 ms budget to
  * 355 ms -- the link would fail its SLA while the aggregate numbers looked acceptable.
  *
  * Bulk traffic is served only from capacity interactive did not use, which is exactly
  * what makes it useful for shaping: it is the filler that fills idle slots and keeps the
  * wire rate flat without ever delaying a user-facing message.
  */
final class Shaper(
    val cfg: ShaperConfig,
    initialKey: Array[Byte],
    initialEpoch: Long,
    rng: Rng,
    val metrics: ShaperMetrics = new ShaperMetrics
):
  import cfg.*

  private final case class Pending(rec: Record, enqueuedAt: Long)

  private val qIntr = mutable.ArrayDeque.empty[Pending]
  private val qBulk = mutable.ArrayDeque.empty[Pending]
  private var bytesIntr = 0L
  private var bytesBulk = 0L

  private val remainingFrags = mutable.HashMap.empty[Long, Int]
  private val submitAt = mutable.HashMap.empty[Long, Long]
  private val msgSvc = mutable.HashMap.empty[Long, ServiceClass]

  private var cellKey: Array[Byte] = initialKey
  private var epoch: Long = initialEpoch

  /** Move to a new epoch's key. Cells already queued are unaffected: the epoch is
    * carried per cell in the header, so the receiver follows automatically. */
  def rekey(newEpoch: Long, newKey: Array[Byte]): Unit =
    epoch = newEpoch
    cellKey = newKey
    seq = 0L

  def currentEpoch: Long = epoch

  private var seq = 0L
  private var lastEmitAt = Long.MinValue / 8
  private var nextAllowedEmitAt = Long.MinValue / 8
  private var nextCoverAt = Long.MinValue / 8

  private var tokens = 0.0
  private var lastTokenAt = 0L
  private var tokenInit = false

  /** Called with (msgId, completeAt) when a message's last fragment leaves. The
    * evaluation uses it for ground truth; the live transport leaves it a no-op. It never
    * influences scheduling. */
  var onMessageComplete: (Long, Long) => Unit = (_, _) => ()

  private def cap: Int = cfg.capacity
  private def brkRate: Boolean = cfg.breakRateForBulkDeadline
  private def pendingRecords: Int = qIntr.length + qBulk.length
  private def pendingBytes: Long = bytesIntr + bytesBulk

  // ------------------------------------------------------------------ input

  /** Queue one application message. `msgId` must be unique per direction. */
  def submit(now: Long, msgId: Long, stream: Array[Byte], svc: ServiceClass = ServiceClass.Interactive): Unit =
    metrics.messagesSubmitted += 1
    metrics.bytesSubmitted += stream.length
    msgSvc(msgId) = svc
    remainingFrags(msgId) = 1
    submitAt(msgId) = now
    val frags = CellCodec.chunkStream(stream, cap)
    if svc == ServiceClass.Bulk then metrics.bulkMessagesSubmitted += 1
    var i = 0
    while i < frags.length do
      val p = Pending(Record(RecKind.Data, msgId, i, frags.length, frags(i)), now)
      if svc == ServiceClass.Bulk then { qBulk.append(p); bytesBulk += CellCodec.RecHdr + frags(i).length }
      else { qIntr.append(p); bytesIntr += CellCodec.RecHdr + frags(i).length }
      i += 1
    remainingFrags(msgId) = frags.length
    metrics.onQueue(pendingBytes)

  // ------------------------------------------------------------------ clock

  def step(now: Long): Vector[Emitted] =
    cfg.timing match
      case TimingMode.Immediate => drainImmediate(now)
      case TimingMode.FixedRate => drainFixedRate(now)
      case TimingMode.Adaptive    => drainAdaptive(now)

  /** When `step` next has work. Must report a time at which `step` will actually emit:
    * every gate checked by the emit path has to be represented here, or the driver's
    * clock stops advancing. (An earlier version omitted the cell-gap gate for cover,
    * reported "now" forever, and hung.) */
  def nextWakeup(now: Long): Long =
    var t = Long.MaxValue
    def at(x: Long): Unit = if x != Long.MaxValue then t = math.min(t, math.max(now, x))

    if cfg.timing == TimingMode.Immediate then
      if pendingRecords > 0 then t = now
      return t

    if cfg.timing == TimingMode.FixedRate then
      refillTokens(now)
      if pendingRecords > 0 then
        at(nextTokenTime)
        // A record at its deadline may be emitted without a token.
        at(math.max(headIntr.map(p => p.enqueuedAt + maxHoldNanos - periodNanos).getOrElse(Long.MaxValue),
                    if brkRate then headBulk.map(p => p.enqueuedAt + bulkHoldNanos - periodNanos).getOrElse(Long.MaxValue)
                    else Long.MaxValue))
      else coverWakeup(at, nextTokenTime)
    else
      // Adaptive: gated by the inter-cell gap, then by the batch window for interactive.
      if headIntr.isDefined then
        val h = headIntr.get
        at(math.max(nextAllowedEmitAt, h.enqueuedAt + batchWindowNanos))
        at(h.enqueuedAt + maxHoldNanos)
      if headBulk.isDefined then
        val h = headBulk.get
        at(nextAllowedEmitAt)
        if brkRate then at(h.enqueuedAt + bulkHoldNanos)
      if pendingRecords == 0 then coverWakeup(at, Long.MinValue / 8)
    t

  private def coverWakeup(at: Long => Unit, extraGate: Long): Unit =
    cover match
      case CoverPolicy.None => ()
      case CoverPolicy.Always =>
        at(math.max(nextAllowedEmitAt, extraGate))
      case CoverPolicy.IdleOnly =>
        val idleReady = math.max(lastEmitAt, Long.MinValue / 8) + coverIdleAfterNanos
        at(math.max(math.max(idleReady, nextCoverAt), math.max(nextAllowedEmitAt, extraGate)))

  private def headIntr: Option[Pending] = qIntr.headOption
  private def headBulk: Option[Pending] = qBulk.headOption

  private def nextTokenTime: Long =
    if !tokenInit then 0L
    else if tokens >= 1.0 then lastTokenAt
    else lastTokenAt + math.ceil((1.0 - tokens) * periodNanos.toDouble).toLong

  // ------------------------------------------------------------------ modes

  /** Baseline only: no shaping, one cell per fragment. */
  private def drainImmediate(now: Long): Vector[Emitted] =
    val out = Vector.newBuilder[Emitted]
    while pendingRecords > 0 do
      val p = if qIntr.nonEmpty then { val x = qIntr.removeHead(); bytesIntr -= CellCodec.RecHdr + x.rec.payload.length; x }
              else { val x = qBulk.removeHead(); bytesBulk -= CellCodec.RecHdr + x.rec.payload.length; x }
      val size = Wire.Overhead + CellCodec.CountLen + CellCodec.RecHdr + p.rec.payload.length
      out += emit(now, Seq(p.rec), size)
    out.result()

  private def drainAdaptive(now: Long): Vector[Emitted] =
    val out = Vector.newBuilder[Emitted]
    var progress = true
    while progress do
      maybeAdaptive(now) match
        case Some(c) => out += c
        case None    => progress = false
    out.result()

  private def maybeAdaptive(now: Long): Option[Emitted] =
    val intr = headIntr
    val bulk = headBulk

    // Hard deadlines are checked BEFORE the inter-cell gap, and they win over it: it is
    // better to break the cadence (and count the break) than to blow the SLA. The gap
    // guard must therefore never be placed above a deadline path -- nextWakeup advertises
    // the deadline time, and if `step` refuses to emit at that time the clock stalls.
    if intr.exists(h => now - h.enqueuedAt >= maxHoldNanos) then
      if now < nextAllowedEmitAt then metrics.deadlineDrivenEmits += 1
      return Some(emitCell(now))
    if brkRate && bulk.exists(h => now - h.enqueuedAt >= bulkHoldNanos) then
      metrics.bulkDeadlineEmits += 1
      return Some(emitCell(now))

    if now < nextAllowedEmitAt then return None

    // Interactive next, coalescing only until its small batch window elapses, or until
    // its backlog would overflow a cell (holding it then adds latency, not batching).
    val intrFull = CellCodec.CountLen + bytesIntr > cap
    if intr.exists(h => now - h.enqueuedAt >= batchWindowNanos) || (intr.isDefined && intrFull) then
      return Some(emitCell(now))

    // Then bulk, as filler: it occupies the slot that interactive did not need.
    if bulk.isDefined then return Some(emitCell(now))

    if pendingRecords == 0 then coverDueAdaptive(now) else None

  private def coverDueAdaptive(now: Long): Option[Emitted] =
    cover match
      case CoverPolicy.None => None
      case CoverPolicy.Always =>
        if now >= nextAllowedEmitAt then Some(emitCover(now)) else None
      case CoverPolicy.IdleOnly =>
        val idleSince = math.max(lastEmitAt, Long.MinValue / 8)
        if now - idleSince >= coverIdleAfterNanos && now >= nextCoverAt && now >= nextAllowedEmitAt then
          val c = emitCover(now)
          nextCoverAt = now + math.max(1L, rng.nextExponential(coverMeanIntervalNanos.toDouble).toLong)
          Some(c)
        else None

  private def drainFixedRate(now: Long): Vector[Emitted] =
    refillTokens(now)
    val out = Vector.newBuilder[Emitted]
    var progress = true
    while progress do
      maybeFixedRate(now) match
        case Some(c) => out += c
        case None    => progress = false
    out.result()

  private def refillTokens(now: Long): Unit =
    if !tokenInit then
      tokenInit = true
      lastTokenAt = now
      tokens = burstCells.toDouble
    else
      val elapsed = now - lastTokenAt
      if elapsed > 0 then
        tokens = math.min(burstCells.toDouble, tokens + elapsed.toDouble / periodNanos)
        lastTokenAt = now

  private def maybeFixedRate(now: Long): Option[Emitted] =
    val urgentIntr = headIntr.exists(h => now - h.enqueuedAt >= math.max(0L, maxHoldNanos - periodNanos))
    val urgentBulk = headBulk.exists(h => now - h.enqueuedAt >= math.max(0L, bulkHoldNanos - periodNanos))

    if tokens >= 1.0 then
      if pendingRecords > 0 then
        tokens -= 1.0
        Some(emitCell(now))
      else cover match
        case CoverPolicy.None => None
        case CoverPolicy.Always =>
          tokens -= 1.0
          Some(emitCover(now))
        case CoverPolicy.IdleOnly =>
          val idleSince = math.max(lastEmitAt, Long.MinValue / 8)
          if now - idleSince >= coverIdleAfterNanos then
            tokens -= 1.0
            Some(emitCover(now))
          else None
    else if urgentIntr then
      // Out of tokens but an interactive message is at its deadline: emit anyway and
      // count it. This is a real cadence break and the evaluation must see it.
      metrics.deadlineDrivenEmits += 1
      Some(emitCell(now))
    else if urgentBulk && pendingRecords > 0 && brkRate then
      metrics.bulkDeadlineEmits += 1
      Some(emitCell(now))
    else None

  // ------------------------------------------------------------------ emission

  /** Build one cell: interactive records first, then bulk records into leftover space. */
  private def emitCell(now: Long): Emitted =
    val chosen = mutable.ArrayBuffer.empty[Record]
    var used = CellCodec.CountLen

    def pull(q: mutable.ArrayDeque[Pending], isIntr: Boolean): Unit =
      var go = true
      while go && q.nonEmpty && chosen.length < CellCodec.MaxCount do
        val p = q.head
        val need = CellCodec.RecHdr + p.rec.payload.length
        if used + need <= cap then
          q.removeHead()
          if isIntr then bytesIntr -= need else bytesBulk -= need
          chosen += p.rec
          used += need
        else go = false

    pull(qIntr, isIntr = true)
    pull(qBulk, isIntr = false)

    if chosen.isEmpty then emitCover(now) else emit(now, chosen.toSeq, cellSize)

  private def emitCover(now: Long): Emitted =
    emit(now, Seq(Record(RecKind.Cover, 0L, 0, 1, Array.emptyByteArray)), cellSize)

  private def emit(now: Long, records: Seq[Record], size: Int): Emitted =
    require(seq <= Wire.MaxSeq, "cell sequence exhausted; rotate epoch")
    val plaintext = CellCodec.pack(records, size - Wire.Overhead, rng)
    val bytes = Wire.sealCell(cellKey, epoch, seq, plaintext, size)
    seq += 1

    val isCover = records.forall(_.kind == RecKind.Cover)
    val msgBytes = records.iterator.filter(_.kind == RecKind.Data).map(_.payload.length).sum
    metrics.cellsSent += 1
    if isCover then metrics.coverCells += 1
    metrics.cellBytes += size
    metrics.cellPayloadBytes += msgBytes
    metrics.onQueue(pendingBytes)

    records.foreach { r =>
      if r.kind == RecKind.Data then
        val left = remainingFrags.getOrElse(r.msgId, 1) - 1
        if left <= 0 then
          remainingFrags.remove(r.msgId)
          submitAt.remove(r.msgId).foreach { t0 =>
            val lat = now - t0
            metrics.latency.record(lat)
            msgSvc.remove(r.msgId) match
              case Some(ServiceClass.Interactive) =>
                metrics.latencyInteractive.record(lat)
                if lat > maxHoldNanos then metrics.deadlineMisses += 1
              case Some(ServiceClass.Bulk) =>
                metrics.latencyBulk.record(lat)
                if lat > bulkHoldNanos then metrics.bulkDeadlineMisses += 1
              case None => ()
          }
          onMessageComplete(r.msgId, now)
        else remainingFrags(r.msgId) = left
    }

    lastEmitAt = now
    if cfg.timing != TimingMode.FixedRate then nextAllowedEmitAt = now + gapNanos()
    Emitted(now, bytes, isCover, records, msgBytes)

  private def gapNanos(): Long =
    val jitter = if jitterNanos > 0 then (rng.nextDouble() * 2.0 - 1.0) * jitterNanos else 0.0
    math.max(0L, math.round(minCellGapNanos.toDouble + jitter))

  def pendingRecordCount: Int = pendingRecords
  def nextSeq: Long = seq
