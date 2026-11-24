package shapelink.eval

import shapelink.sim.*
import shapelink.core.Rng
import scala.collection.mutable

/** Label derived for one window from ground truth. */
final case class WindowLabels(cls: Int, amount: Int, vip: Int, hasTraffic: Boolean)

final case class LeakReport(
    label: String,
    nClasses: Int,
    accuracy: Double,
    majorityBaseline: Double,
    macroF1: Double,
    /** Empirical mutual information between predicted label and true label, nats. */
    mutualInformation: Double,
    /** Marginal entropy of the true label over the test set, nats. */
    labelEntropy: Double,
    /** Fraction of label entropy still recoverable by the adversary, in [0,1]. */
    residualLeak: Double
):
  def leakPercent: Double = residualLeak * 100.0

object Evaluator:

  /** Build window-level dataset from a simulation result.
    *
    * Labels are the *dominant* class / amount within the window from ground truth, and
    * whether a VIP event completed in it. This is what an analyst would care about:
    * "what kind of business is happening in this window", not per-message recovery.
    */
  def windows(
      res: SimResult,
      windowNanos: Long,
      minMessages: Int = 1
  ): (Array[Array[Double]], Array[WindowLabels]) =
    val end = res.truth.iterator.map(_.completeAt).maxOption.getOrElse(0L)
    val ws = Windowing.fixed(end + windowNanos, windowNanos)
    val feats = mutable.ArrayBuffer.empty[Array[Double]]
    val labels = mutable.ArrayBuffer.empty[WindowLabels]
    ws.foreach { w =>
      val inWin = res.truth.filter(t => t.completeAt >= w.startNanos && t.completeAt < w.endNanos)
      val f = Features.compute(res.trace, w)
      if inWin.length >= minMessages then
        val byClass = inWin.groupBy(_.cls).view.mapValues(_.length).toMap
        val byAmount = inWin.groupBy(_.amount).view.mapValues(_.length).toMap
        val domClass = TxnClass.all.indexOf(byClass.maxBy(_._2)._1)
        val domAmount = AmountBucket.all.indexOf(byAmount.maxBy(_._2)._1)
        val vip = if inWin.exists(_.vip) then 1 else 0
        feats += f.vector
        labels += WindowLabels(domClass, domAmount, vip, hasTraffic = true)
      else
        feats += f.vector
        labels += WindowLabels(cls = -1, amount = -1, vip = 0, hasTraffic = false)
    }
    (feats.toArray, labels.toArray)

  /** Train on the first `trainFraction` of windows, test on the rest.
    *
    * Splitting by time, never at random, is essential: adjacent windows share traffic
    * state, and a random split would let the adversary memorise neighbours and
    * overstate the leak.
    */
  def evaluateLabelled(
      res: SimResult,
      windowNanos: Long,
      labelName: String,
      minMessages: Int = 1,
      trainFraction: Double = 0.5,
      epochs: Int = 400
  ): (LeakReport, Array[Array[Double]], Array[WindowLabels]) =
    val (xAll, yAll) = windows(res, windowNanos, minMessages)
    val n = xAll.length
    val cut = math.max(1, (n * trainFraction).toInt)

    def extract(y: WindowLabels): Int = labelName match
      case "class"  => y.cls
      case "amount" => y.amount
      case "vip"    => y.vip
      case other    => throw new IllegalArgumentException(s"unknown label $other")

    val keep = (i: Int) => yAll(i).hasTraffic || labelName == "vip"
    val trainIdx = (0 until cut).filter(keep)
    val testIdx = (cut until n).filter(keep)
    val nClasses = labelName match
      case "class"  => TxnClass.all.length
      case "amount" => AmountBucket.all.length
      case "vip"    => 2

    if trainIdx.length < 2 * nClasses || testIdx.isEmpty then
      val empty = LeakReport(labelName, nClasses, 0, 0, 0, 0, 0, 1.0)
      (empty, xAll, yAll)
    else
      val xTrain = trainIdx.map(xAll).toArray
      val yTrain = trainIdx.map(i => extract(yAll(i))).toArray
      val xTest = testIdx.map(xAll).toArray
      val yTest = testIdx.map(i => extract(yAll(i))).toArray

      val adv = new SoftmaxAdversary(nClasses, epochs = epochs)
      adv.fit(xTrain, yTrain)
      val preds = xTest.map(adv.predict)

      val rep = report(labelName, nClasses, yTest, preds, xTrain.length, xTest.length)
      (rep, xAll, yAll)
    end if

  private def report(name: String, nClasses: Int, yTrue: Array[Int], yPred: Array[Int], nTrain: Int, nTest: Int): LeakReport =
    val n = yTrue.length
    val correct = yTrue.indices.count(i => yTrue(i) == yPred(i))
    val acc = correct.toDouble / n
    val freqs = yTrue.groupBy(identity).view.mapValues(_.length).toMap
    val majority = freqs.values.max.toDouble / n

    val f1s = (0 until nClasses).flatMap { c =>
      val tp = yTrue.indices.count(i => yTrue(i) == c && yPred(i) == c)
      val fp = yTrue.indices.count(i => yTrue(i) != c && yPred(i) == c)
      val fn = yTrue.indices.count(i => yTrue(i) == c && yPred(i) != c)
      if tp + fp + fn == 0 then None
      else if tp == 0 then Some(0.0)
      else Some(2.0 * tp / (2.0 * tp + fp + fn))
    }
    val macroF1 = if f1s.isEmpty then 0.0 else f1s.sum / f1s.length

    // Empirical mutual information I(Y; Yhat) from the confusion matrix.
    val pairs = yTrue.indices.groupBy(i => (yTrue(i), yPred(i))).view.mapValues(_.length).toMap
    val yFreq = yTrue.groupBy(identity).view.mapValues(_.length.toDouble / n).toMap
    val pFreq = yPred.groupBy(identity).view.mapValues(_.length.toDouble / n).toMap
    var mi = 0.0
    pairs.foreach { case ((t, p), cnt) =>
      val pJoint = cnt.toDouble / n
      val denom = yFreq(t) * pFreq(p)
      if denom > 0 then mi += pJoint * math.log(pJoint / denom)
    }
    val entropy = -yFreq.values.filter(_ > 0).map(p => p * math.log(p)).sum
    val residual = if entropy <= 1e-9 then 0.0 else math.max(0.0, math.min(1.0, mi / entropy))

    LeakReport(name, nClasses, acc, majority, macroF1, mi, entropy, residual)
