package shapelink.sim

import shapelink.core.Rng

/** The application-level transaction classes on a payment link.
  *
  * These are the labels the security assessment says an on-path observer can infer
  * today. They are modelled with deliberately *overlapping but distinct* signatures:
  * message sizes and burst shapes differ by class, which is exactly the signal we are
  * trying to suppress.
  */
enum TxnClass(val label: String):
  case Retail extends TxnClass("retail")             // frequent, small, low value
  case BatchSettlement extends TxnClass("settlement") // scheduled, large payloads
  case CorporateTransfer extends TxnClass("corporate") // medium, few, high value
  case FxConversion extends TxnClass("fx")            // paired request/response, spiky
  case Query extends TxnClass("query")                // tiny balance/status lookups

object TxnClass:
  val all: IndexedSeq[TxnClass] = IndexedSeq(Retail, BatchSettlement, CorporateTransfer, FxConversion, Query)

  /** Which latency budget a class of business traffic belongs to.
    *
    * Retail and query are user-facing; settlement is a scheduled batch job and corporate
    * transfers are confirmed asynchronously, so both can be held long enough to be spread
    * across idle link slots instead of dumped in a burst.
    */
  def serviceClass(c: TxnClass): shapelink.shape.ServiceClass = c match
    case Retail | Query => shapelink.shape.ServiceClass.Interactive
    case BatchSettlement | CorporateTransfer | FxConversion => shapelink.shape.ServiceClass.Bulk

/** Amount bucket, coarse enough to be what an analyst would actually care about. */
enum AmountBucket(val label: String):
  case Micro extends AmountBucket("<1k")
  case Small extends AmountBucket("1k-50k")
  case Medium extends AmountBucket("50k-1M")
  case Large extends AmountBucket(">1M")

object AmountBucket:
  val all: IndexedSeq[AmountBucket] = IndexedSeq(Micro, Small, Medium, Large)

/** One business event: something that happened and produced application messages. */
final case class Event(atNanos: Long, cls: TxnClass, amount: AmountBucket, vip: Boolean)

/** One application message produced by an event. */
final case class AppMessage(seq: Long, atNanos: Long, cls: TxnClass, amount: AmountBucket, vip: Boolean, payload: Array[Byte])

/** Workload description. Kept explicit so an evaluation can cite the exact scenario. */
final case class WorkloadConfig(
    durationNanos: Long = 3600L * 1_000_000_000L, // one simulated hour
    /** Average business events per second, overall. */
    eventsPerSecond: Double = 40.0,
    /** Relative mix of transaction classes. */
    classWeights: Map[TxnClass, Double] = Map(
      TxnClass.Retail -> 0.62,
      TxnClass.Query -> 0.18,
      TxnClass.CorporateTransfer -> 0.10,
      TxnClass.FxConversion -> 0.07,
      TxnClass.BatchSettlement -> 0.03
    ),
    /** VIP client traffic is a small fraction of events but is what the assessment says
      * leaks most damagingly ("大客户资金动向"). Modelled as a separate Poisson process
      * whose events are tagged `vip = true` and concentrated in business hours.
      */
    vipEventsPerSecond: Double = 0.8,
    /** Number of messages an event emits (min, max), per class. */
    messagesPerEvent: Map[TxnClass, (Int, Int)] = Map(
      TxnClass.Retail -> (1, 2),
      TxnClass.Query -> (1, 1),
      TxnClass.CorporateTransfer -> (1, 3),
      TxnClass.FxConversion -> (2, 4),
      TxnClass.BatchSettlement -> (6, 24)
    ),
    /** Payload size distribution per class, log-normal(meanLog, sigmaLog) in bytes. */
    sizeModel: Map[TxnClass, (Double, Double)] = Map(
      TxnClass.Retail -> (math.log(180.0), 0.45),
      TxnClass.Query -> (math.log(90.0), 0.30),
      TxnClass.CorporateTransfer -> (math.log(900.0), 0.55),
      TxnClass.FxConversion -> (math.log(1400.0), 0.40),
      TxnClass.BatchSettlement -> (math.log(9000.0), 0.70)
    ),
    /** Amount bucket probabilities per class. */
    amountModel: Map[TxnClass, Map[AmountBucket, Double]] = Map(
      TxnClass.Retail -> Map(AmountBucket.Micro -> 0.80, AmountBucket.Small -> 0.18, AmountBucket.Medium -> 0.02, AmountBucket.Large -> 0.0),
      TxnClass.Query -> Map(AmountBucket.Micro -> 1.0),
      TxnClass.CorporateTransfer -> Map(AmountBucket.Micro -> 0.05, AmountBucket.Small -> 0.30, AmountBucket.Medium -> 0.45, AmountBucket.Large -> 0.20),
      TxnClass.FxConversion -> Map(AmountBucket.Micro -> 0.02, AmountBucket.Small -> 0.13, AmountBucket.Medium -> 0.45, AmountBucket.Large -> 0.40),
      TxnClass.BatchSettlement -> Map(AmountBucket.Micro -> 0.0, AmountBucket.Small -> 0.05, AmountBucket.Medium -> 0.30, AmountBucket.Large -> 0.65)
    )
):
  def totalClassWeight: Double = classWeights.values.sum

/** Generates a reproducible synthetic workload.
  *
  * The point is not to be a perfect model of any particular payment network, but to be
  * a *stated, replayable* one: every number the evaluation reports is relative to this
  * workload definition, and the same seed reproduces it exactly. Operators should
  * replace the distributions with measured ones from their own link; the interface
  * (`Event`/`AppMessage` streams) is what the rest of the system consumes.
  */
object TrafficModel:
  def generate(cfg: WorkloadConfig, seed: Long): Vector[AppMessage] =
    val rng = new Rng(seed)
    val events = generateEvents(cfg, rng.split())
    var msgSeq = 0L
    val out = Vector.newBuilder[AppMessage]
    events.foreach { ev =>
      val (lo, hi) = cfg.messagesPerEvent.getOrElse(ev.cls, (1, 1))
      val n = lo + rng.nextInt(hi - lo + 1)
      var i = 0
      while i < n do
        val (meanLog, sigmaLog) = cfg.sizeModel(ev.cls)
        val raw = rng.logNormal(meanLog, sigmaLog)
        // A message carries a small envelope around its application payload.
        val len = math.max(16, math.min(256 * 1024, raw.toLong)).toInt
        val payload = Array.ofDim[Byte](len)
        rng.nextBytes(payload) // content is irrelevant and must not be relied on
        // Messages of an event are spread over a short span: a request/response rhythm.
        val spread = if n == 1 then 0L else (rng.nextDouble() * n * 2_000_000.0).toLong
        out += AppMessage(msgSeq, ev.atNanos + spread, ev.cls, ev.amount, ev.vip, payload)
        msgSeq += 1
        i += 1
    }
    out.result().sortBy(_.atNanos)

  private def generateEvents(cfg: WorkloadConfig, rng: Rng): Vector[Event] =
    val bg = poissonProcess(cfg.durationNanos, cfg.eventsPerSecond, rng.split())
    val vip = poissonProcess(cfg.durationNanos, cfg.vipEventsPerSecond, rng.split())
    val clsArr = cfg.classWeights.keys.toIndexedSeq
    val clsW = clsArr.map(cfg.classWeights).toArray
    val bgEvents = bg.map { t =>
      val cls = clsArr(rng.pick(clsW))
      Event(t, cls, drawAmount(cfg, cls, rng), vip = false)
    }
    val vipEvents = vip.map { t =>
      // VIP traffic is skewed to corporate transfers and FX.
      val cls = if rng.nextDouble() < 0.7 then TxnClass.CorporateTransfer else TxnClass.FxConversion
      Event(t, cls, drawAmount(cfg, cls, rng), vip = true)
    }
    (bgEvents ++ vipEvents).sortBy(_.atNanos)

  private def drawAmount(cfg: WorkloadConfig, cls: TxnClass, rng: Rng): AmountBucket =
    val m = cfg.amountModel(cls)
    val buckets = m.keys.toIndexedSeq
    buckets(rng.pick(buckets.map(m).toArray))

  /** Arrival times of a Poisson process with the given mean rate over [0, duration). */
  private def poissonProcess(durationNanos: Long, ratePerSec: Double, rng: Rng): Vector[Long] =
    if ratePerSec <= 0.0 then Vector.empty
    else
      val meanGap = 1e9 / ratePerSec
      val out = Vector.newBuilder[Long]
      var t = 0.0
      var go = true
      while go do
        t += rng.nextExponential(meanGap)
        if t < durationNanos.toDouble then out += t.toLong else go = false
      out.result()
