package shapelink.cli

import shapelink.core.*
import shapelink.shape.*
import shapelink.sim.*
import shapelink.eval.*
import shapelink.ops.*

object Main:
  def main(args: Array[String]): Unit =
    args.headOption match
      case Some("simulate") => simulate(args.drop(1))
      case Some("sweep")    => sweep(args.drop(1))
      case Some("inspect")  => inspect(args.drop(1))
      case Some("loopback") => loopback(args.drop(1))
      case Some("selftest") => selftest()
      case _ =>
        println(usage)
        if args.nonEmpty then sys.exit(2)

  val usage = """shapelink -- traffic-shape obfuscation for a bank-to-PSP link

commands:
  selftest              run correctness + leakage sanity checks
  simulate [opts]       run one operating point and print a report
      --mode immediate|adaptive|fixed
      --window MS       evaluation window (default 1000)
      --seed N
      --duration S      simulated seconds (default 600)
      --rate N          business events/sec (default 40)
      --cell N          cell size bytes (default 1200)
      --hold MS         max hold (default 25)
      --period MS       fixed-rate period (default 2)
      --burst N         fixed-rate burst depth (default 8)
      --cover none|idle|always
  sweep [opts]          compare operating points, same workload
      accepts the same options; prints a table across modes
  loopback [N]          end-to-end over a real TCP socket on a real clock
  inspect [opts]        per-class feature distributions inside evaluation windows
"""

  final case class Opts(
      mode: TimingMode = TimingMode.Adaptive,
      windowMs: Long = 1000,
      seed: Long = 1,
      durationS: Long = 600,
      rate: Double = 40.0,
      cell: Int = 1200,
      holdMs: Long = 25,
      periodMs: Long = 2,
      burst: Int = 8,
      cover: CoverPolicy = CoverPolicy.IdleOnly,
      breakRate: Boolean = true
  )

  def parseOpts(args: Array[String]): Opts =
    var o = Opts()
    var i = 0
    while i < args.length do
      def next(): String = { i += 1; if i >= args.length then sys.error(s"missing value for ${args(i - 1)}"); args(i) }
      args(i) match
        case "--mode" => o = o.copy(mode = next() match {
            case "immediate" => TimingMode.Immediate
            case "adaptive"  => TimingMode.Adaptive
            case "fixed"     => TimingMode.FixedRate
            case m           => sys.error(s"unknown mode $m")
          })
        case "--window"   => o = o.copy(windowMs = next().toLong)
        case "--seed"     => o = o.copy(seed = next().toLong)
        case "--duration" => o = o.copy(durationS = next().toLong)
        case "--rate"     => o = o.copy(rate = next().toDouble)
        case "--cell"     => o = o.copy(cell = next().toInt)
        case "--hold"     => o = o.copy(holdMs = next().toLong)
        case "--period"   => o = o.copy(periodMs = next().toLong)
        case "--burst"    => o = o.copy(burst = next().toInt)
        case "--no-break" => o = o.copy(breakRate = false)
        case "--cover"    => o = o.copy(cover = next() match {
            case "none"   => CoverPolicy.None
            case "idle"   => CoverPolicy.IdleOnly
            case "always" => CoverPolicy.Always
            case c        => sys.error(s"unknown cover policy $c")
          })
        case other => sys.error(s"unknown option $other")
      i += 1
    o

  def shaperFor(o: Opts): ShaperConfig =
    ShaperConfig(
      cellSize = o.cell,
      timing = o.mode,
      maxHoldNanos = o.holdMs * 1_000_000L,
      periodNanos = math.max(1L, o.periodMs) * 1_000_000L,
      burstCells = o.burst,
      cover = o.cover,
      breakRateForBulkDeadline = o.breakRate
    )

  def workloadFor(o: Opts): WorkloadConfig =
    WorkloadConfig(durationNanos = o.durationS * 1_000_000_000L, eventsPerSecond = o.rate)

  def simulate(args: Array[String]): Unit =
    val o = parseOpts(args)
    val res = Simulator.run(shaperFor(o), workloadFor(o), o.seed)
    val windowNanos = o.windowMs * 1_000_000L
    val start = System.nanoTime()
    val cls = Evaluator.evaluateLabelled(res, windowNanos, "class")
    val amt = Evaluator.evaluateLabelled(res, windowNanos, "amount")
    val vip = Evaluator.evaluateLabelled(res, windowNanos, "vip")
    val evalMs = (System.nanoTime() - start) / 1e6

    println(s"=== shapelink simulate  mode=${o.mode} cell=${o.cell}B window=${o.windowMs}ms seed=${o.seed} ===")
    println()
    println("-- wire --")
    println(f"cells=${res.trace.cells.length}%,d  distinct_cell_sizes=${res.trace.distinctSizes.size}  total_bytes=${res.trace.totalBytes}%,d")
    println()
    println("-- shaper --")
    println(res.metrics.snapshot)
    println(s"delivered_messages=${res.messagesDelivered}  delivery_errors=${res.deliveryErrors}")
    println()
    println("-- leakage (adversary trained on first half, tested on second half) --")
    println(f"${"label"}%-10s ${"classes"}%8s ${"acc"}%8s ${"majority"}%10s ${"macroF1"}%9s ${"residualLeak"}%14s")
    Seq(cls._1, amt._1, vip._1).foreach { r =>
      println(f"${r.label}%-10s ${r.nClasses}%8d ${r.accuracy * 100}%7.1f%% ${r.majorityBaseline * 100}%9.1f%% ${r.macroF1}%9.3f ${r.residualLeak * 100}%13.1f%%")
    }
    println(f"(evaluation took ${evalMs}%.0f ms)")

  def inspect(args: Array[String]): Unit =
    val o = parseOpts(args)
    val res = Simulator.run(shaperFor(o), workloadFor(o), o.seed)
    val windowNanos = o.windowMs * 1_000_000L
    val (xAll, yAll) = Evaluator.windows(res, windowNanos)
    println(s"=== inspect mode=${o.mode} cover=${o.cover} cell=${o.cell}B window=${o.windowMs}ms ===")
    println(f"windows=${xAll.length}  cells=${res.trace.cells.length}  cover_cells=${res.metrics.coverCells}")
    println()
    // Per-window cell-count distribution, split by dominant class: this is the signal
    // the adversary actually uses. If the distributions overlap, the window is safe.
    val byClass = yAll.indices.filter(i => yAll(i).hasTraffic).groupBy(i => yAll(i).cls)
    println(f"${"class"}%-12s ${"n"}%6s ${"cells/win"}%11s ${"cells/sd"}%9s ${"bytes/win"}%12s")
    byClass.toSeq.sortBy(_._1).foreach { case (c, idxs) =>
      val cells = idxs.map(i => xAll(i)(0))
      val bytes = idxs.map(i => xAll(i)(1))
      val m = cells.sum / cells.length
      val sd = math.sqrt(cells.map(v => (v - m) * (v - m)).sum / cells.length)
      val bm = bytes.sum / bytes.length
      val name = if c >= 0 then TxnClass.all(c).label else "none"
      println(f"$name%-12s ${idxs.length}%6d $m%11.1f $sd%9.1f $bm%12.0f")
    }
    println()
    val idle = yAll.count(!_.hasTraffic)
    println(s"idle_windows=$idle / ${yAll.length}  (${100.0 * idle / math.max(1, yAll.length)}%.1f%%)")
    val zeroCellIdle = yAll.indices.count(i => !yAll(i).hasTraffic && xAll(i)(0) == 0.0)
    println(s"of those, windows with zero cells: $zeroCellIdle")

  def sweep(args: Array[String]): Unit =
    val base = parseOpts(args)
    val modes = Seq(
      ("immediate", base.copy(mode = TimingMode.Immediate, cover = CoverPolicy.None)),
      ("adaptive", base.copy(mode = TimingMode.Adaptive, cover = CoverPolicy.IdleOnly)),
      ("adaptive+always", base.copy(mode = TimingMode.Adaptive, cover = CoverPolicy.Always)),
      ("fixed", base.copy(mode = TimingMode.FixedRate, cover = CoverPolicy.Always))
    )
    val windowNanos = base.windowMs * 1_000_000L
    println(f"${"mode"}%-16s ${"cells/s"}%8s ${"rateCV"}%7s ${"overhd"}%7s ${"intrP99"}%8s ${"bulkP99"}%8s ${"miss"}%6s ${"classLeak"}%10s ${"amtLeak"}%8s ${"vipLeak"}%8s")
    modes.foreach { case (name, o) =>
      val res = Simulator.run(shaperFor(o), workloadFor(o), base.seed)
      val secs = math.max(1e-9, res.trace.durationNanos / 1e9)
      val cps = res.trace.cells.length / secs
      // Rate stability: coefficient of variation of per-window cell counts. A shaped link
      // should be near zero -- the rate itself must carry no information.
      val (xAll, _) = Evaluator.windows(res, windowNanos)
      val cc = xAll.map(_(0)).filter(_ >= 0)
      val cm = if cc.isEmpty then 0.0 else cc.sum / cc.length
      val rcvs = if cc.isEmpty || cm == 0 then 0.0
                 else math.sqrt(cc.map(v => (v - cm) * (v - cm)).sum / cc.length) / cm
      val ip = res.metrics.latencyInteractive.summary.p99Ms
      val bp = res.metrics.latencyBulk.summary.p99Ms
      val cls = Evaluator.evaluateLabelled(res, windowNanos, "class")._1
      val amt = Evaluator.evaluateLabelled(res, windowNanos, "amount")._1
      val vip = Evaluator.evaluateLabelled(res, windowNanos, "vip")._1
      val miss = res.metrics.deadlineMisses + res.metrics.bulkDeadlineMisses
      println(f"$name%-16s $cps%8.0f $rcvs%7.3f ${res.metrics.paddingOverhead * 100}%6.1f%% $ip%7.1f $bp%8.1f $miss%6d ${cls.residualLeak * 100}%9.1f%% ${amt.residualLeak * 100}%7.1f%% ${vip.residualLeak * 100}%7.1f%%")
    }

  /** A few invariants that must never regress, printed as PASS/FAIL. */
  def loopback(args: Array[String]): Unit =
    val n = args.headOption.map(_.toInt).getOrElse(1000)
    val r = shapelink.transport.LoopbackDemo.run(n)
    println("=== loopback (real TCP, real clock) ===")
    println(f"messages sent/received : ${r.sentMessages}%d / ${r.receivedMessages}%d")
    println(f"cells sent             : ${r.cellsSent}%d  rejected: ${r.cellsRejected}%d")
    println(f"distinct cell sizes    : ${r.distinctCellSizes}%d")
    println(f"bytes on wire          : ${r.bytesOnWire}%d")
    println(f"elapsed                : ${r.elapsedMs}%.0f ms")
    println(f"interactive p99        : ${r.interactiveP99Ms}%.2f ms")
    println(f"bulk p99               : ${r.bulkP99Ms}%.2f ms")
    if r.receivedMessages < r.sentMessages then
      println(s"NOTE: ${r.sentMessages - r.receivedMessages} messages were not confirmed within the demo timeout")

  def selftest(): Unit =
    var ok = true
    def check(name: String)(cond: => Boolean): Unit =
      val r: Boolean =
        try cond
        catch
          case e: Throwable =>
            println(s"  ($name threw ${e.getClass.getSimpleName}: ${e.getMessage})")
            false
      println(f"${if r then "PASS" else "FAIL"}%s $name")
      if !r then ok = false

    val cfg = ShaperConfig(timing = TimingMode.Adaptive)
    val wl = WorkloadConfig(durationNanos = 120L * 1_000_000_000L, eventsPerSecond = 60.0)
    val res = Simulator.run(cfg, wl, seed = 42)

    check("every cell is the same size on the wire")(res.trace.distinctSizes == Set(cfg.cellSize))
    check("no delivery errors")(res.deliveryErrors == 0)
    check("all submitted messages reassembled")(res.messagesDelivered == res.metrics.messagesSubmitted.toInt)
    // Interactive is the SLA that matters: a retail payment cannot sit behind a
    // settlement burst. Bulk is allowed to use its (much looser) own budget.
    check("no interactive message exceeded its hold budget")(res.metrics.deadlineMisses == 0)
    check("interactive p99 within budget + margin")(
      res.metrics.latencyInteractive.summary.p99Ms <= cfg.maxHoldNanos / 1e6 + 2.0)
    check("interactive never waited near the bulk budget")(
      res.metrics.latencyInteractive.summary.maxMs <= cfg.maxHoldNanos / 1e6 + 2.0)
    check("bulk messages met their own looser budget a majority of the time")(
      res.metrics.latencyBulk.summary.count == 0 || res.metrics.latencyBulk.summary.p50Ms <= cfg.bulkHoldNanos / 1e6)

    // Tamper detection: flip one byte in a sealed cell and confirm it is rejected.
    val key = Crypto.keyFromSeed(7L)
    val rng = new Rng(9L)
    val pt = CellCodec.pack(Seq(Record(RecKind.Data, 1L, 0, 1, Array[Byte](1, 2, 3))), cfg.capacity, rng)
    val cell = Wire.sealCell(key, 1L, 1L, pt, cfg.cellSize)
    val tampered = cell.clone(); tampered(tampered.length / 2) = (tampered(tampered.length / 2) ^ 0x01).toByte
    check("AEAD rejects a tampered cell")(Wire.openCell(key, tampered).isEmpty)
    check("AEAD accepts an intact cell")(Wire.openCell(key, cell).exists(_._2.sameElements(pt)))

    // Sequence renumbering must break authentication (bound as AAD).
    val hdrPatched = cell.clone()
    hdrPatched(13) = (hdrPatched(13) ^ 0x01).toByte
    check("AEAD rejects a renumbered/spliced header")(Wire.openCell(key, hdrPatched).isEmpty)

    println(if ok then "\nALL CHECKS PASSED" else "\nSOME CHECKS FAILED")
    if !ok then sys.exit(1)
