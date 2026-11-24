package shapelink.ops

import scala.collection.mutable

/** Latency summary in milliseconds. */
final case class LatencySummary(
    count: Long,
    meanMs: Double,
    p50Ms: Double,
    p90Ms: Double,
    p95Ms: Double,
    p99Ms: Double,
    maxMs: Double
)

object LatencySummary:
  val empty = LatencySummary(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

/** Exact percentiles over recorded samples (nanoseconds). */
final class LatencyRecorder(maxSamples: Int = 4_000_000):
  private val samples = mutable.ArrayBuffer.empty[Long]
  private var overflow = 0L

  def record(nanos: Long): Unit =
    if samples.length < maxSamples then samples += math.max(0L, nanos)
    else overflow += 1

  def overflowed: Long = overflow

  def summary: LatencySummary =
    if samples.isEmpty then LatencySummary.empty
    else
      val a = samples.toArray
      java.util.Arrays.sort(a)
      val n = a.length
      def p(q: Double): Double =
        val idx = math.min(n - 1, math.max(0, math.round(q * (n - 1)).toInt))
        a(idx) / 1e6
      val mean = a.iterator.map(_.toDouble).sum / n / 1e6
      LatencySummary(n, mean, p(0.5), p(0.9), p(0.95), p(0.99), a(n - 1) / 1e6)

/** Per-direction counters for the shaper. Contains no payload, ever.
  *
  * Latency is tracked per service class because the link carries two very different
  * traffic types and a single p99 would hide the one that matters.
  */
final class ShaperMetrics:
  var messagesSubmitted: Long = 0L
  var bytesSubmitted: Long = 0L
  var cellsSent: Long = 0L
  var coverCells: Long = 0L
  var cellBytes: Long = 0L
  var cellPayloadBytes: Long = 0L
  var deadlineMisses: Long = 0L
  var bulkDeadlineMisses: Long = 0L
  var bulkDeadlineEmits: Long = 0L
  var bulkMessagesSubmitted: Long = 0L
  var maxQueueBytes: Long = 0L
  var deadlineDrivenEmits: Long = 0L

  /** Overall, interactive (retail/query), and bulk (settlement/corporate/fx). */
  val latency = new LatencyRecorder
  val latencyInteractive = new LatencyRecorder
  val latencyBulk = new LatencyRecorder

  def onQueue(q: Long): Unit = if q > maxQueueBytes then maxQueueBytes = q

  def paddingOverhead: Double =
    if cellBytes <= 0 then 0.0 else (cellBytes - cellPayloadBytes).toDouble / cellBytes

  def coverFraction: Double =
    if cellsSent <= 0 then 0.0 else coverCells.toDouble / cellsSent

  private def fmt(name: String, ls: LatencySummary): String =
    f"$name%-12s count=${ls.count} mean=${ls.meanMs}%.2f p50=${ls.p50Ms}%.2f p95=${ls.p95Ms}%.2f p99=${ls.p99Ms}%.2f max=${ls.maxMs}%.2f"

  def snapshot: String =
    val bi = f"""messages_submitted=$messagesSubmitted bytes_submitted=$bytesSubmitted
                |cells_sent=$cellsSent cover_cells=$coverCells
                |cell_bytes=$cellBytes payload_bytes=$cellPayloadBytes
                |padding_overhead=${paddingOverhead * 100}%.1f%% cover_fraction=${coverFraction * 100}%.1f%%
                |deadline_misses=$deadlineMisses deadline_driven_emits=$deadlineDrivenEmits
                |bulk_deadline_misses=$bulkDeadlineMisses bulk_deadline_emits=$bulkDeadlineEmits max_queue_bytes=$maxQueueBytes""".stripMargin
    Seq(bi, fmt("latency_all", latency.summary),
        fmt("latency_intr", latencyInteractive.summary),
        fmt("latency_bulk", latencyBulk.summary)).mkString("\n")
