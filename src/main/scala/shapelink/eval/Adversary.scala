package shapelink.eval

import shapelink.sim.*
import shapelink.core.Rng
import scala.collection.mutable

/** Evenly spaced observation windows over a trace. */
object Windowing:
  final case class Window(startNanos: Long, endNanos: Long)
  def fixed(durationNanos: Long, windowNanos: Long): Vector[Window] =
    require(windowNanos > 0)
    val out = Vector.newBuilder[Window]
    var s = 0L
    while s < durationNanos do
      out += Window(s, math.min(durationNanos, s + windowNanos))
      s += windowNanos
    out.result()

/** Feature vector an adversary computes from a trace within one window.
  *
  * Every feature is computed strictly from what the wire shows: cell arrival times and
  * cell sizes. Sizes are constant after shaping, so size features collapse -- that
  * collapse is itself one of the results we report.
  */
final case class WindowFeatures(
    window: Windowing.Window,
    cellCount: Int,
    bytes: Long,
    meanGapNanos: Double,
    gapCv: Double,        // coefficient of variation of inter-arrival gaps
    burstiness: Double,   // (var - mean)/mean of gaps; >0 bursty, ~0 Poisson, <0 regular
    maxGapNanos: Long,
    activeFraction: Double, // fraction of sub-slots with at least one cell
    sizeMean: Double,
    sizeCv: Double,
    /** Largest number of cells seen between two arbitrary 1 ms sub-bounds. */
    peakCellsPerMs: Int
):
  def vector: Array[Double] =
    Array(cellCount.toDouble, bytes.toDouble, meanGapNanos, gapCv, burstiness,
      maxGapNanos.toDouble, activeFraction, sizeMean, sizeCv, peakCellsPerMs.toDouble)

object Features:
  val names: IndexedSeq[String] = IndexedSeq(
    "cell_count", "bytes", "mean_gap_ns", "gap_cv", "burstiness",
    "max_gap_ns", "active_fraction", "size_mean", "size_cv", "peak_cells_per_ms"
  )

  def compute(trace: WireTrace, window: Windowing.Window, subSlotNanos: Long = 1_000_000L): WindowFeatures =
    val cells = trace.cells.filter(c => c.atNanos >= window.startNanos && c.atNanos < window.endNanos)
    val n = cells.length
    val span = math.max(1L, window.endNanos - window.startNanos).toDouble
    if n == 0 then
      WindowFeatures(window, 0, 0L, span, 0.0, 0.0, window.endNanos - window.startNanos, 0.0, 0.0, 0.0, 0)
    else
      val bytes = cells.iterator.map(_.bytes.toLong).sum
      val gaps = (1 until n).map(i => (cells(i).atNanos - cells(i - 1).atNanos).toDouble).toArray
      val (meanGap, cv, burst) =
        if gaps.isEmpty then (span, 0.0, 0.0)
        else
          val m = gaps.sum / gaps.length
          val v = gaps.iterator.map(g => (g - m) * (g - m)).sum / gaps.length
          val sd = math.sqrt(v)
          (m, if m > 0 then sd / m else 0.0, if m > 0 then (v - m) / m else 0.0)
      val maxGap = if gaps.isEmpty then (window.endNanos - window.startNanos) else gaps.max.toLong
      // Active fraction and peak sub-slot occupancy.
      val slots = math.max(1L, (window.endNanos - window.startNanos) / subSlotNanos)
      val counts = Array.fill(math.min(slots, 5_000_000L).toInt)(0)
      cells.foreach { c =>
        val idx = ((c.atNanos - window.startNanos) / subSlotNanos).toInt
        if idx >= 0 && idx < counts.length then counts(idx) += 1
      }
      val active = counts.count(_ > 0).toDouble / math.max(1, counts.length)
      val peak = if counts.isEmpty then 0 else counts.max
      val sizes = cells.map(_.bytes.toDouble)
      val sm = sizes.sum / n
      val svar = sizes.iterator.map(s => (s - sm) * (s - sm)).sum / n
      val scv = if sm > 0 then math.sqrt(svar) / sm else 0.0
      WindowFeatures(window, n, bytes, meanGap, cv, burst, maxGap, active, sm, scv, peak)

/** A simple, deterministic multinomial logistic-regression adversary.
  *
  * This is the standard way to put a *number* on "how much does the shape leak": treat
  * the trace-derived features as inputs and try to recover a sensitive label
  * (transaction class, amount bucket, VIP flag). Accuracy well above the class prior,
  * and cross-entropy well below the prior entropy, means the shape still leaks.
  *
  * Full-batch gradient descent with L2 and a fixed iteration count rather than an SGD
  * library dependency: it is deterministic, has no hidden hyperparameter search, and
  * converges reliably on the feature scales here (features are standardised first).
  */
final class SoftmaxAdversary(
    val nClasses: Int,
    val epochs: Int = 400,
    val lr: Double = 0.20,
    val l2: Double = 1e-3
):
  private var w: Array[Array[Double]] = null // nClasses x (d+1), last col is bias
  private var mu: Array[Double] = null
  private var sd: Array[Double] = null

  def fit(x: Array[Array[Double]], y: Array[Int]): Unit =
    require(x.nonEmpty, "no training data")
    val n = x.length
    val d = x(0).length
    mu = Array.ofDim[Double](d)
    sd = Array.ofDim[Double](d)
    var j = 0
    while j < d do
      var s = 0.0
      var i = 0
      while i < n do { s += x(i)(j); i += 1 }
      val m = s / n
      var v = 0.0
      i = 0
      while i < n do { val t = x(i)(j) - m; v += t * t; i += 1 }
      mu(j) = m
      sd(j) = math.max(1e-9, math.sqrt(v / n))
      j += 1

    w = Array.fill(nClasses, d + 1)(0.0)
    val xs = x.map(standardise)
    var ep = 0
    while ep < epochs do
      val grad = Array.fill(nClasses, d + 1)(0.0)
      var i = 0
      while i < n do
        val p = probs(xs(i))
        val yi = y(i)
        var c = 0
        while c < nClasses do
          val err = p(c) - (if c == yi then 1.0 else 0.0)
          if err != 0.0 then
            var k = 0
            while k < d do { grad(c)(k) += err * xs(i)(k); k += 1 }
            grad(c)(d) += err
          c += 1
        i += 1
      var c = 0
      while c < nClasses do
        var k = 0
        while k <= d do
          val reg = if k < d then l2 * w(c)(k) else 0.0
          w(c)(k) -= lr * (grad(c)(k) / n + reg)
          k += 1
        c += 1
      ep += 1
    end while

  private def standardise(x: Array[Double]): Array[Double] =
    val out = Array.ofDim[Double](x.length)
    var j = 0
    while j < x.length do { out(j) = (x(j) - mu(j)) / sd(j); j += 1 }
    out

  private def probs(xs: Array[Double]): Array[Double] =
    val logits = Array.ofDim[Double](nClasses)
    var c = 0
    while c < nClasses do
      var s = w(c)(xs.length)
      var k = 0
      while k < xs.length do { s += w(c)(k) * xs(k); k += 1 }
      logits(c) = s
      c += 1
    val mx = logits.max
    var s = 0.0
    c = 0
    while c < nClasses do { logits(c) = math.exp(logits(c) - mx); s += logits(c); c += 1 }
    c = 0
    while c < nClasses do { logits(c) /= s; c += 1 }
    logits

  def predictProba(raw: Array[Double]): Array[Double] = probs(standardise(raw))
  def predict(raw: Array[Double]): Int = { val p = predictProba(raw); p.indexOf(p.max) }
