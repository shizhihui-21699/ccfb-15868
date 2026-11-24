package shapelink.shape

import shapelink.core.Wire

/** Service class of a message, deciding its latency budget and cover behaviour.
  *
  * This split is the single most important operational lever. Retail/query messages are
  * user-facing and need a few milliseconds. Settlement and corporate transfers are
  * batched and can tolerate hundreds of milliseconds. Forcing one deadline on both makes
  * the bulk traffic's bursts blow through the fixed-rate cadence -- which is exactly what
  * the sweep showed before this split existed (666 cells/s against a 500 cells/s target).
  */
enum ServiceClass:
  /** User-facing: must meet `interactiveHoldNanos`. Message timeliness dominates. */
  case Interactive
  /** Latency-tolerant: may be held far longer, so it can be spread to fill idle slots
    * instead of being dumped at once. This is where most of the shaping budget comes from.
    */
  case Bulk

/** How cells are placed on the wire.
  *
  * These are the three points on the latency/bandwidth/leakage trade-off curve; the
  * evaluation harness sweeps them so the operator can pick a defensible operating point
  * instead of guessing.
  */
enum TimingMode:
  /** No shaping. One cell per message, emitted the instant it is submitted.
    *   - added latency: ~0
    *   - overhead: 0
    *   - leaks: everything about arrival timing and, at this layer, cell count.
    * Kept only as the measurement baseline.
    */
  case Immediate

  /** Adaptive batching: coalesce until a cell fills, otherwise flush within
    * `batchWindow` (coalescing several small messages), hard-flush at `maxHold`.
    * Cheap, low latency, but the wire rate still tracks the arrival rate -- it hides
    * *message boundaries* well and *volume rate* only partially.
    */
  case Adaptive

  /** Strict clocking. A cell leaves every `periodNanos` regardless of arrivals; an
    * empty slot is filled with a cover cell. Up to `burstCells` may leave back to back
    * so a large transfer does not take `n * period` to drain.
    *
    * Because emission times are independent of arrival times, the wire timing carries
    * no information about application traffic at all; what remains is the (shaped)
    * volume rate and whatever the token bucket reveals about large bursts.
    */
  case FixedRate

/** When to emit a cover cell (only meaningful for Adaptive; FixedRate pads empty slots). */
enum CoverPolicy:
  /** Never pad idle periods. Silence is visible as silence. */
  case None

  /** Emit a cover cell only after the link has been idle for `idleAfterNanos`,
    * at a Poisson rate. Erases "nothing happened" without paying full idle bandwidth.
    */
  case IdleOnly

  /** Fill every slot. Used with FixedRate to make rate constant. */
  case Always

/** Shaper tuning. Defaults are a starting point for a payment link, not a recommendation:
  * `simulate`/`sweep` should be used to pick values against the real workload.
  */
final case class ShaperConfig(
    cellSize: Int = 1200,
    timing: TimingMode = TimingMode.Adaptive,
    /** Hard latency budget for user-facing messages. A message may never be held
      * longer than this; if the link cannot keep up, the shaper breaks cadence rather
      * than this budget, and counts that as a leak.
      */
    maxHoldNanos: Long = 25_000_000L, // 25 ms
    /** Latency budget for bulk traffic. Deliberately loose: settlement does not need to
      * arrive in 25 ms, and relaxing it is what buys the shape.
      */
    bulkHoldNanos: Long = 400_000_000L, // 400 ms
    /** Adaptive: deliberate wait that lets a second small message join the same cell. */
    batchWindowNanos: Long = 4_000_000L, // 4 ms
    /** Adaptive: floor on spacing between cells, so a burst is never emitted back to back. */
    minCellGapNanos: Long = 1_500_000L, // 1.5 ms
    /** FixedRate: target spacing between cells. */
    periodNanos: Long = 2_000_000L, // 2 ms -> 500 cells/s
    /** FixedRate: token-bucket depth, i.e. how many cells may burst back to back. */
    burstCells: Int = 8,
    /** Adaptive: random timing jitter added to the gap (uniform in +/- this value). */
    jitterNanos: Long = 600_000L, // 0.6 ms
    /** When bulk traffic cannot drain within its own deadline at the shaped rate, which
      * do we sacrifice?
      *
      *   - true  (default): emit anyway. The bulk deadline is met; the wire rate exceeds
      *     the target during backlog, and that excess is itself visible to an observer.
      *   - false: never exceed the rate. Bulk messages miss their deadline, but the wire
      *     rate stays flat, which is the whole point of shaping.
      *
      * Measured on the default workload this choice moves fixed-rate output from ~537
      * cells/s against a 500 target (burst past the bucket) to a hard 500, at the cost of
      * bulk p99 rising above its budget. Neither is free; the evaluation prints both so
      * the choice is made with numbers rather than by taste.
      */
    breakRateForBulkDeadline: Boolean = true,
    cover: CoverPolicy = CoverPolicy.IdleOnly,
    /** Adaptive+IdleOnly: idle time before a cover cell is considered. */
    coverIdleAfterNanos: Long = 30_000_000L, // 30 ms
    /** Adaptive+IdleOnly: mean Poisson interval between cover cells once idle. */
    coverMeanIntervalNanos: Long = 50_000_000L // 50 ms
):
  require(cellSize > Wire.Overhead + 16, s"cellSize $cellSize too small")
  require(maxHoldNanos > 0 && batchWindowNanos >= 0 && minCellGapNanos >= 0)
  require(periodNanos > 0 && burstCells >= 1)
  require(bulkHoldNanos >= maxHoldNanos, "bulk budget should not be tighter than interactive")

  def capacity: Int = Wire.capacity(cellSize)
  def maxRecordPayload: Int = shapelink.core.CellCodec.maxRecordPayload(capacity)
  def holdFor(c: ServiceClass): Long = c match
    case ServiceClass.Interactive => maxHoldNanos
    case ServiceClass.Bulk        => bulkHoldNanos
