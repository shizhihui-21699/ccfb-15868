package shapelink.core

/** SplitMix64: small, fast, fully specified PRNG.
  *
  * Experiments must be reproducible bit-for-bit, so we do not use
  * `java.util.Random` or `SplittableRandom` (whose algorithms are not
  * part of the Java specification and may change between JDKs).
  */
final class Rng(seed: Long):
  private var st: Long = seed
  private var spareGauss: Double = Double.NaN

  def nextLong(): Long =
    st += 0x9E3779B97F4A7C15L
    var z = st
    z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L
    z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL
    z ^ (z >>> 31)

  /** Uniform in [0, n). Unbiased (rejection sampling on a 63-bit draw). */
  def nextInt(n: Int): Int =
    require(n > 0, s"bound must be positive, got $n")
    val bound = n.toLong
    val limit = Long.MaxValue - (Long.MaxValue % bound)
    var r = nextLong() >>> 1
    while r >= limit do r = nextLong() >>> 1
    (r % bound).toInt

  /** Uniform in [0, 1). 53 bits of mantissa, as in the reference implementation. */
  def nextDouble(): Double = (nextLong() >>> 11).toDouble / 9007199254740992.0 // 2^53

  def nextBytes(a: Array[Byte]): Unit =
    var i = 0
    while i < a.length do
      var v = nextLong()
      var j = 0
      while j < 8 && i < a.length do
        a(i) = (v & 0xFF).toByte
        v >>>= 8
        i += 1
        j += 1

  def nextBoolean(): Boolean = (nextLong() & 1L) != 0L

  /** Standard normal via Box-Muller, with the usual spare-value cache. */
  def nextGaussian(): Double =
    if !spareGauss.isNaN then
      val v = spareGauss
      spareGauss = Double.NaN
      v
    else
      var u1 = nextDouble()
      while u1 <= 1e-12 do u1 = nextDouble() // avoid log(0)
      val u2 = nextDouble()
      val r = math.sqrt(-2.0 * math.log(u1))
      val a = 2.0 * math.Pi * u2
      spareGauss = r * math.sin(a)
      r * math.cos(a)

  /** Exponential with the given mean (Poisson inter-arrival times). */
  def nextExponential(mean: Double): Double = -mean * math.log(1.0 - nextDouble())

  def logNormal(meanLog: Double, sigmaLog: Double): Double =
    math.exp(meanLog + sigmaLog * nextGaussian())

  /** Draw an index proportional to `weights` (must be non-empty, non-negative). */
  def pick(weights: Array[Double]): Int =
    require(weights.nonEmpty)
    var total = 0.0
    var i = 0
    while i < weights.length do
      total += weights(i)
      i += 1
    require(total > 0.0, "weights must sum to a positive value")
    var r = nextDouble() * total
    var idx = 0
    while idx < weights.length - 1 do
      r -= weights(idx)
      if r <= 0.0 then return idx
      idx += 1
    weights.length - 1

  /** An independent stream derived deterministically from this one. */
  def split(): Rng = new Rng(nextLong())
